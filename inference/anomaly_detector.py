import torch
import torch.nn as nn
import numpy as np
import pandas as pd
import os
from .model import LSTMAutoencoder


class AnomalyDetector:
    def __init__(self, model_path='model/lstm_autoencoder_model.pth', 
                 threshold=0.280038, max_seq_len=100, vocab_size=36):
        self.vocab_size = vocab_size
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.threshold = threshold
        self.max_seq_len = max_seq_len
        
        self.model = LSTMAutoencoder(
            vocab_size=vocab_size,
            embed_dim=8,
            hidden_dim=16,
            num_layers=1,
            dropout=0.3
        ).to(self.device)
        
        if os.path.exists(model_path):
            checkpoint = torch.load(model_path, map_location=self.device)
            if 'model_state_dict' in checkpoint:
                self.model.load_state_dict(checkpoint['model_state_dict'])
            else:
                self.model.load_state_dict(checkpoint)
            self.model.eval()
            print(f"Model loaded from {model_path}")
        else:
            raise FileNotFoundError(f"Model file not found: {model_path}")
    
    def pad_sequence(self, seq, max_len, pad_value=0):
        if len(seq) > max_len:
            return seq[:max_len]
        return seq + [pad_value] * (max_len - len(seq))
    
    def calculate_reconstruction_error(self, sequence):
        padded = self.pad_sequence(sequence, self.max_seq_len) 
        seq_tensor = torch.tensor([padded], dtype=torch.long).to(self.device)
        criterion = nn.CrossEntropyLoss(ignore_index=0, reduction='none')
        
        with torch.no_grad():
            output = self.model(seq_tensor)
            
            output_flat = output.view(-1, self.vocab_size)
            target_flat = seq_tensor.view(-1)
            
            token_losses = criterion(output_flat, target_flat)
            
            mask = target_flat != 0
            if mask.sum() > 0:
                error = token_losses[mask].mean().item()
            else:
                error = 0.0
            
            return float(error)
    
    def predict_single_sequence(self, sequence):
        if len(sequence) < 2:
            return {
                'is_anomaly': False,
                'reconstruction_error': 0.0,
                'confidence': 0.0,
                'message': 'Sequence too short (minimum 2 events required)'
            }
        
        error = self.calculate_reconstruction_error(sequence)
        is_anomaly = error > self.threshold
        
        confidence = abs(error - self.threshold) / self.threshold
        confidence = min(confidence, 1.0)
        
        return {
            'is_anomaly': bool(is_anomaly),
            'reconstruction_error': float(error),
            'threshold': float(self.threshold),
            'confidence': float(confidence)
        }
    
    def predict_batch_sequences(self, sequences):
        results = []
        for seq in sequences:
            results.append(self.predict_single_sequence(seq))
        return results
