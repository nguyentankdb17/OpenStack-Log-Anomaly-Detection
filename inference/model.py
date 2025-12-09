import torch
import torch.nn as nn

class LSTMAutoencoder(nn.Module):
    def __init__(self, vocab_size, embed_dim=8, hidden_dim=16, num_layers=1, dropout=0.3):
        super().__init__()
        self.vocab_size = vocab_size
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers
        
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        
        self.encoder = nn.LSTM(
            embed_dim, hidden_dim, num_layers=num_layers,
            batch_first=True, dropout=0
        )
        
        self.decoder = nn.LSTM(
            embed_dim, hidden_dim, num_layers=num_layers,
            batch_first=True, dropout=0
        )
        
        self.dropout = nn.Dropout(dropout)
        self.output_layer = nn.Linear(hidden_dim, vocab_size)
    
    def forward(self, sequence):
        batch_size, seq_length = sequence.size()
        
        embedded = self.embedding(sequence)
        _, (hidden, cell) = self.encoder(embedded)
        
        predictions = []
        decoder_input = sequence[:, 0]
        decoder_state = (hidden, cell)
        
        for t in range(seq_length):
            emb = self.embedding(decoder_input).unsqueeze(1)
            decoder_output, decoder_state = self.decoder(emb, decoder_state)
            decoder_output = self.dropout(decoder_output.squeeze(1))
            logits = self.output_layer(decoder_output)
            predictions.append(logits)
            
            if t + 1 < seq_length:
                decoder_input = sequence[:, t + 1]
        
        output = torch.stack(predictions, dim=1)
        return output
