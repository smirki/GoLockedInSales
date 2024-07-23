import os

def create_or_update_file(file_path, contents):
    # Create directories if they do not exist
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    
    # Write the contents to the file
    with open(file_path, 'w') as file:
        file.write(contents)
    print(f"File created/updated: {file_path}")

def process_output_file(output_file):
    with open(output_file, 'r') as file:
        lines = file.readlines()

    current_path = None
    current_contents = []
    
    for line in lines:
        if line.startswith('Path:'):
            # If there is already a file being processed, write its contents
            if current_path:
                create_or_update_file(current_path, ''.join(current_contents))
            
            # Start processing a new file
            current_path = line.split(': ')[1].strip()
            current_contents = []
        elif line.startswith('Directory:'):
            continue  # Ignore this line
        elif line.startswith('Contents:'):
            continue  # Ignore this line
        else:
            current_contents.append(line)

    # Write the last file being processed
    if current_path:
        create_or_update_file(current_path, ''.join(current_contents))

if __name__ == "__main__":
    # Path to the output file
    output_file = 'output.txt'
    print(f"Processing output file: {output_file}")
    process_output_file(output_file)
    print("Processing complete.")
