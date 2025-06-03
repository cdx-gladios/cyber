# utils.py
def load_log_file(path):
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        return f.readlines()

def save_report(path, lines):
    with open(path, 'w', encoding='utf-8') as f:
        for line in lines:
            f.write(line + "\n")