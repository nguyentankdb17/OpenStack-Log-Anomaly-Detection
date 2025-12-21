from logparser.Drain import LogParser

input_dir = '../data/'
output_dir = 'result/'
log_file = 'openstack_test.log'

log_format = '<Logfile> <Date> <Time> <Pid> <Level> <Component> \[<Context>\] <Content>'

regex = [
    r'\breq-[0-9a-f]{8,}\b',
    r'\breq-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b',
    r'\binstance-[0-9a-f]{8}\b',
    r'\[instance:\s+[0-9a-f-]{36}\]',
    r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b',
    r'/[A-Za-z0-9._\-]+(?:/[A-Za-z0-9._\-]+)*',
    r'\b\d{1,3}(?:\.\d{1,3}){3}\b',  # IP addresses
    r'\b\d{4}-\d{2}-\d{2}\b',  # Dates
    r'\b\d{2}:\d{2}:\d{2}(?:\.\d+)?\b',  # Times
    r'\b\d+\.\d+\b',  # Decimal numbers
    r'\b\d+(?:\.\d+)?\s*MB\b',  # Memory MB
    r'\b\d+(?:\.\d+)?\s*GB\b',  # Memory GB
    r'\b\d+\s*v?CPUs?\b',  # CPUs
    r'\b\d+(?:\.\d+)?\s*seconds?\b',  # Seconds
    r'\b\d{4,}\b(?!\s*\])'
]

st = 0.3
depth = 6

# Initialize parser
parser = LogParser(
    log_format, 
    indir=input_dir, 
    outdir=output_dir, 
    depth=depth, 
    st=st, 
    rex=regex
)

parser.parse(log_file)
