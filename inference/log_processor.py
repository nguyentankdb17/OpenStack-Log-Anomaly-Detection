import re
import pandas as pd
from datetime import datetime
from logparser.Drain import LogParser
import tempfile
import os
from sklearn.preprocessing import LabelEncoder


class OpenStackLogProcessor:    
    def __init__(self):
        self.log_format = '<Logfile> <Date> <Time> <Pid> <Level> <Component> \[<Context>\] <Content>'
        
        self.regex = [
            r'\breq-[0-9a-f]{8,}\b',
            r'\breq-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b',
            r'\binstance-[0-9a-f]{8}\b',
            r'\[instance:\s+[0-9a-f-]{36}\]',
            r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b',
            r'/[A-Za-z0-9._\-]+(?:/[A-Za-z0-9._\-]+)*',
            r'\b\d{1,3}(?:\.\d{1,3}){3}\b',
            r'\b\d{4}-\d{2}-\d{2}\b',
            r'\b\d{2}:\d{2}:\d{2}(?:\.\d+)?\b',
            r'\b\d+(?:\.\d+)?\s*MB\b',
            r'\b\d+(?:\.\d+)?\s*GB\b',
            r'\b\d+\s*v?CPUs?\b',
            r'\b\d+(?:\.\d+)?\s*seconds?\b',
            r'\b\d{4,}\b(?!\s*\])',
        ]
        
        self.st = 0.3
        self.depth = 6
        
        self.event_mapping = None
        self._load_event_mapping()
    
    def _load_event_mapping(self):
        self.event_mapping = {}
    
    def parse_logs(self, log_text):
        with tempfile.TemporaryDirectory() as temp_dir:
            # Write log text to temporary file
            log_file = os.path.join(temp_dir, 'temp.log')
            with open(log_file, 'w') as f:
                f.write(log_text)
            
            # Initialize Drain parser
            parser = LogParser(
                self.log_format,
                indir=temp_dir,
                outdir=temp_dir,
                depth=self.depth,
                st=self.st,
                rex=self.regex
            )
            
            # Parse the log file
            parser.parse('temp.log')
            
            # Read the parsed result
            structured_file = os.path.join(temp_dir, 'temp.log_structured.csv')
            df = pd.read_csv(structured_file)
            
            # Read templates
            templates_file = os.path.join(temp_dir, 'temp.log_templates.csv')
            templates_df = pd.read_csv(templates_file)
        
        return df, templates_df
    
    def prepare_for_detection(self, df, templates_df, vocab_size=36):
        df['Datetime'] = pd.to_datetime(df['Date'] + ' ' + df['Time'])
        
        df = df.rename(columns={'Context': 'RequestID'})
        
        encoder = LabelEncoder()
        encoded_ids = encoder.fit_transform(df["EventId"])
        
        # If encoded_id >= vocab_size, map to vocab_size-1 (unknown token)
        max_valid_id = vocab_size - 1
        df["EventID"] = [min(eid + 1, max_valid_id) for eid in encoded_ids]
        
        # Sort by datetime
        df = df.sort_values(by='Datetime')
        
        # Select relevant columns
        result_df = df[[
            'Datetime', 'Pid', 'Level', 'Component', 'RequestID', 
            'Content', 'EventTemplate', 'EventID', 'ParameterList'
        ]].copy()
        
        return result_df
    
    def process_raw_logs(self, log_text):
        df, templates_df = self.parse_logs(log_text)
        processed_df = self.prepare_for_detection(df, templates_df)
        
        return processed_df
    
    def extract_sequences(self, df):
        sequences = df.groupby('RequestID')['EventID'].apply(list).to_dict()
        sequences = {req_id: seq for req_id, seq in sequences.items() if seq != ["-"]}
        return sequences
