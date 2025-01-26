import hashlib
import os

def sha256_hash(file_path):
    """Compute the SHA256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for byte_block in iter(lambda: f.read(4096), b''):
            sha256.update(byte_block)
    return sha256.hexdigest()

def generate_hashes(directory):
    """Generate SHA256 hashes for all files in the directory."""
    hashes = {}
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            hashes[file_path] = sha256_hash(file_path)
    return hashes

def save_hashes(hashes, output_file):
    """Save the hashes to a file."""
    with open(output_file, 'w') as f:
        for file_path, hash_value in hashes.items():
            f.write(f'{file_path}: {hash_value}\n')

if __name__ == "__main__":
    # Set the directory to the current directory
    directory = '.'
    # Set the output file name
    output_file = 'hashes.txt'
    
    # Generate hashes
    hashes = generate_hashes(directory)
    # Save hashes to a file
    save_hashes(hashes, output_file)
    
    print(f'SHA256 hashes have been saved to {output_file}')
