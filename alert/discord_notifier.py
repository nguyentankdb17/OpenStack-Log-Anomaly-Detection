import requests
import json
from datetime import datetime

class DiscordNotifier:
    def __init__(self, webhook_url, enabled=True):
        self.webhook_url = webhook_url
        self.enabled = enabled
        
        if self.enabled and webhook_url:
            self._test_connection()
    
    def _test_connection(self):
        try:
            response = requests.get(self.webhook_url, timeout=5)
            if response.status_code == 405 or response.status_code == 200:
                print(f"Discord webhook connected")
                return True
            print(f"Discord webhook connection failed: {response.status_code}")
            return False
        except Exception as e:
            print(f"Error testing Discord connection: {e}")
            return False
    
    def send_message(self, content=None, embeds=None):
        if not self.enabled or not self.webhook_url:
            return False
        
        try:
            payload = {}
            
            if content:
                payload['content'] = content[:2000]
            
            if embeds:
                payload['embeds'] = embeds
            
            response = requests.post(
                self.webhook_url,
                json=payload,
                timeout=10
            )
            
            if response.status_code == 204 or response.status_code == 200:
                return True
            else:
                print(f"Failed to send Discord message: HTTP {response.status_code}")
                print(response.text[:200])
                return False
                
        except Exception as e:
            print(f"Error sending Discord message: {e}")
            return False
    
    def send_anomaly_alert(self, result):
        if not result or len(result.get('anomalies', [])) == 0:
            return False
        
        summary = result['summary']
        anomalies = result['anomalies']
        
        embed = {
            "title": "🚨 ANOMALY ALERT - OpenStack Logs",
            "color": 0xFF0000,
            "timestamp": datetime.utcnow().isoformat(),
            "fields": []
        }
        
        embed["fields"].append({
            "name": "📊 Summary",
            "value": (
                f"**Total sequences:** {summary['total_sequences']}\n"
                f"**Anomalies detected:** {summary['anomalies']}\n"
                f"**Anomaly rate:** {summary['anomaly_rate']}%\n"
                f"**Total log entries:** {summary['total_log_entries']}"
            ),
            "inline": False
        })
        
        for i, anomaly in enumerate(anomalies[:5], 1):
            level_emoji = "📝"
            if anomaly.get('log_entries') and len(anomaly['log_entries']) > 0:
                first_log = anomaly['log_entries'][0]
                level = first_log.get('Level', 'N/A')
                level_emoji = {
                    'ERROR': '❌',
                    'WARNING': '⚠️',
                    'CRITICAL': '🔥',
                    'INFO': 'ℹ️',
                    'DEBUG': '🐞'
                }.get(level, '📝')
            
            value_text = (
                f"**Request ID:** `{anomaly['request_id'][:30]}...`\n"
                f"**Error:** {anomaly['reconstruction_error']:.4f} (threshold: {anomaly['threshold']:.4f})\n"
                f"**Confidence:** {anomaly['confidence']:.2%}\n"
                f"**Sequence length:** {anomaly['sequence_length']}"
            )
            
            if anomaly.get('log_entries') and len(anomaly['log_entries']) > 0:
                first_log = anomaly['log_entries'][0]
                level = first_log.get('Level', 'N/A')
                component = first_log.get('Component', 'N/A')
                content = first_log.get('Content', '')[:100]
                
                value_text += f"\n**Level:** {level}\n**Component:** {component}"
                if content:
                    value_text += f"\n**Content:** {content}..."
            
            embed["fields"].append({
                "name": f"{level_emoji} Anomaly #{i}",
                "value": value_text,
                "inline": False
            })
        
        if len(anomalies) > 5:
            embed["footer"] = {
                "text": f"... and {len(anomalies) - 5} more anomalies. Full details saved to JSON file."
            }
        else:
            embed["footer"] = {
                "text": "Full details saved to JSON file"
            }
        
        success = self.send_message(embeds=[embed])
        
        if success:
            print(f"Discord alert sent: {summary['anomalies']} anomalies")
        else:
            print(f"Failed to send Discord alert")
        
        return success
    
    def send_startup_notification(self, monitor_info):
        embed = {
            "title": "✅ OpenStack Log Monitor Started",
            "color": 0x00FF00,
            "timestamp": datetime.utcnow().isoformat(),
            "fields": [
                {
                    "name": "🔧 Configuration",
                    "value": (
                        f"**Elasticsearch:** {monitor_info.get('es_host', 'N/A')}\n"
                        f"**Index:** {monitor_info.get('index_pattern', 'N/A')}\n"
                        f"**Interval:** {monitor_info.get('interval', 3)} minutes\n"
                        f"**Threshold:** {monitor_info.get('threshold', 0.28)}"
                    ),
                    "inline": False
                }
            ],
            "footer": {
                "text": "🔔 You will receive alerts when anomalies are detected"
            }
        }
        
        return self.send_message(embeds=[embed])
