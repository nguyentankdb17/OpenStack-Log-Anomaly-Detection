import os
import sys
import json
import time
from datetime import datetime, timedelta
import requests
import pandas as pd
import schedule
from dotenv import load_dotenv

load_dotenv()
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from inference.anomaly_detector import AnomalyDetector
from inference.log_processor import OpenStackLogProcessor
from alert.discord_notifier import DiscordNotifier


class LogMonitor:    
    def __init__(self, es_host, es_username, es_password, index_pattern, output_dir, discord_webhook_url, discord_enabled=True, save_json=True):
        self.es_host = es_host
        self.es_username = es_username
        self.es_password = es_password
        self.index_pattern = index_pattern
        self.output_dir = output_dir
        self.save_json = save_json
        os.makedirs(output_dir, exist_ok=True)
        
        print(f"\nTesting connection to Elasticsearch at {es_host}...")
        self.es_connected = False
        
        try:
            response = requests.get(es_host, timeout=5)
            if response.status_code == 200:
                info = response.json()
                print(f"  Connected to Elasticsearch")
                print(f"  Cluster: {info.get('name', 'N/A')}")
                print(f"  Version: {info.get('version', {}).get('number', 'N/A')}")
                self.es_connected = True
                
                # Check for matching indices
                indices_url = f"{es_host}/_cat/indices?format=json"
                response = requests.get(indices_url, timeout=5)
                if response.status_code == 200:
                    indices = response.json()
                    matching = [i for i in indices if index_pattern.replace('*', '') in i['index']]
                    print(f"  Matching indices: {len(matching)}")
                    if matching:
                        total_docs = sum(int(i.get('docs.count', 0)) for i in matching)
                        print(f"  Total documents: {total_docs:,}")
            else:
                print(f"Connection failed: HTTP {response.status_code}")
        except Exception as e:
            print(f" Error connecting to Elasticsearch: {e}")
            print(f" Verify: curl {es_host}")
        
        try:
            BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            model_path = os.path.join(BASE_DIR, 'model', 'lstm_autoencoder_model.pth')
            
            self.detector = AnomalyDetector(
                model_path=model_path,
                threshold=0.280038,
                max_seq_len=100,
                vocab_size=36
            )
            print("Anomaly detector initialized")
        except Exception as e:
            print(f"Error initializing detector: {e}")
            self.detector = None
        
        try:
            self.log_processor = OpenStackLogProcessor()
            print("Log processor initialized")
        except Exception as e:
            print(f"Error initializing log processor: {e}")
            self.log_processor = None
        
        self.discord = DiscordNotifier(
            webhook_url=discord_webhook_url,
            enabled=discord_enabled
        )
        
        self.last_query_time = None
    
    def fetch_logs_from_elasticsearch(self, time_range_minutes=3):
        if not self.es_connected:
            print("Elasticsearch not connected")
            return None
        
        try:
            now = datetime.utcnow()
            start_time = now - timedelta(minutes=time_range_minutes)
            
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {
                                "range": {
                                    "@timestamp": {
                                        "gte": start_time.isoformat(),
                                        "lte": now.isoformat()
                                    }
                                }
                            }
                        ]
                    }
                },
                "sort": [
                    {"@timestamp": {"order": "asc"}}
                ],
                "size": 10000
            }
            
            print(f"\nQuerying Elasticsearch from {start_time.strftime('%Y-%m-%d %H:%M:%S')} to {now.strftime('%Y-%m-%d %H:%M:%S')}")
            
            search_url = f"{self.es_host}/{self.index_pattern}/_search"
            response = requests.post(search_url, json=query, timeout=30)
            
            if response.status_code != 200:
                print(f"Search failed: HTTP {response.status_code}")
                print(response.text[:500])
                return None
            
            result = response.json()
            hits = result['hits']['hits']
            
            if len(hits) == 0:
                print("No new logs found in this time window")
                return None
            
            log_lines = []
            for hit in hits:
                source = hit['_source']
                
                logfile = source.get('log.file.path', 'unknown.log').lower()
                message = source.get('message', source.get('log', source.get('text', '')))
                
                if message:
                    log_lines.append(f"{logfile}: {message.strip()}")
            
            if not log_lines:
                print("No valid log messages found")
                return None
            
            log_text = '\n'.join(log_lines)
            print(f"Extracted {len(log_lines)} log lines")
            
            return log_text
            
        except Exception as e:
            print(f"Error fetching logs from Elasticsearch: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def detect_anomalies(self, log_text):
        if self.detector is None or self.log_processor is None:
            print("Detector or log processor not initialized")
            return None
        
        try:
            print("Processing logs...")
            
            processed_df = self.log_processor.process_raw_logs(log_text)
            print(f"Parsed {len(processed_df)} log entries")
            
            sequences = self.log_processor.extract_sequences(processed_df)
            print(f"Extracted {len(sequences)} sequences")
            
            if len(sequences) == 0:
                print("No sequences found")
                return None
            
            sequence_list = list(sequences.values())
            request_ids = list(sequences.keys())
            
            predictions = self.detector.predict_batch_sequences(sequence_list)
            
            anomalies = []
            for i, pred in enumerate(predictions):
                if pred.get('is_anomaly', False):
                    anomaly_data = {
                        'request_id': request_ids[i],
                        'sequence': sequence_list[i],
                        'sequence_length': len(sequence_list[i]),
                        'reconstruction_error': pred['reconstruction_error'],
                        'threshold': pred['threshold'],
                        'confidence': pred['confidence'],
                        'timestamp': datetime.utcnow().isoformat()
                    }
                    
                    request_logs = processed_df[processed_df['RequestID'] == request_ids[i]]
                    anomaly_data['log_entries'] = request_logs[['Datetime', 'Level', 'Component', 'Content', 'EventTemplate']].to_dict('records')
                    
                    anomalies.append(anomaly_data)
            
            total_sequences = len(predictions)
            total_anomalies = len(anomalies)
            normal_sequences = total_sequences - total_anomalies
            
            result = {
                'timestamp': datetime.utcnow().isoformat(),
                'summary': {
                    'total_log_entries': len(processed_df),
                    'total_sequences': total_sequences,
                    'anomalies': total_anomalies,
                    'normal': normal_sequences,
                    'anomaly_rate': round(total_anomalies / total_sequences * 100, 2) if total_sequences > 0 else 0
                },
                'anomalies': anomalies
            }
            
            print(f"Detection complete: {total_anomalies} anomalies found out of {total_sequences} sequences")
            
            return result
            
        except Exception as e:
            print(f"Error detecting anomalies: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def save_anomalies(self, result):
        if result is None or len(result.get('anomalies', [])) == 0:
            print("No anomalies to save")
            return
        
        self.discord.send_anomaly_alert(result)
        
        if self.save_json:
            try:
                timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
                filename = f"anomalies_{timestamp}.json"
                filepath = os.path.join(self.output_dir, filename)
                
                with open(filepath, 'w', encoding='utf-8') as f:
                    json.dump(result, f, indent=2, ensure_ascii=False, default=str)
                
                print(f"Anomalies saved to {filepath}")
                print(f"Total anomalies: {len(result['anomalies'])}")
                
            except Exception as e:
                print(f"Error saving anomalies: {e}")
    
    def run_detection_cycle(self):
        print("\n" + "="*80)
        print(f"Starting detection cycle at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*80)
        
        log_text = self.fetch_logs_from_elasticsearch(time_range_minutes=3)
        
        if log_text is None:
            print("No logs to process in this cycle")
            return
        
        result = self.detect_anomalies(log_text)
        
        if result is None:
            print("Detection failed")
            return
        
        if len(result.get('anomalies', [])) > 0:
            self.save_anomalies(result)
        else:
            print("No anomalies detected in this cycle")
        
        print(f"\nCycle completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    def start(self, interval_minutes=3):
        print("\n" + "="*80)
        print("OpenStack Log Anomaly Detection Monitor")
        print("="*80)
        
        if not self.es_connected:
            print("\n Cannot start: Elasticsearch not connected")
            return
        
        if self.detector is None or self.log_processor is None:
            print("\n Cannot start: Detector or log processor not initialized")
            return
        
        print("\nRunning initial detection cycle...")
        self.run_detection_cycle()
        
        schedule.every(interval_minutes).minutes.do(self.run_detection_cycle)
        
        print(f"\n Scheduler started. Will run every {interval_minutes} minutes.")
        print("Press Ctrl+C to stop.\n")
        
        try:
            while True:
                schedule.run_pending()
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n\nStopping monitor...")


def main():
    ES_HOST = os.getenv("ES_HOST", "http://localhost:9200")
    ES_USERNAME = os.getenv("ES_USERNAME", "elastic")
    ES_PASSWORD = os.getenv("ES_PASSWORD", "")
    INDEX_PATTERN = os.getenv("ES_INDEX_PATTERN", "nova-*")
    OUTPUT_DIR = "anomaly_results"
    INTERVAL_MINUTES = 3
    
    DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "")
    DISCORD_ENABLED = os.getenv("DISCORD_ENABLED", "true").lower() == "true"
    SAVE_JSON = os.getenv("SAVE_JSON", "true").lower() == "true"
    
    monitor = LogMonitor(
        es_host=ES_HOST,
        es_username=ES_USERNAME,
        es_password=ES_PASSWORD,
        index_pattern=INDEX_PATTERN,
        output_dir=OUTPUT_DIR,
        discord_webhook_url=DISCORD_WEBHOOK_URL,
        discord_enabled=DISCORD_ENABLED,
        save_json=SAVE_JSON
    )
    
    monitor.start(interval_minutes=INTERVAL_MINUTES)


if __name__ == '__main__':
    main()
