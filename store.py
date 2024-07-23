import os

def collect_contents(directory, output_file, skip_dirs, skip_files):
    script_path = os.path.abspath(__file__)
    with open(output_file, 'w') as out_file:
        for root, dirs, files in os.walk(directory):
            # Skip directories in the skip_dirs list
            dirs[:] = [d for d in dirs if os.path.join(root, d) not in skip_dirs]

            for file in files:
                file_path = os.path.join(root, file)
                
                # Skip the script itself and any files in the skip_files list
                if file_path == script_path or file in skip_files:
                    continue

                out_file.write(f"Path: {file_path}\n")
                out_file.write(f"Directory: {root}\n")
                out_file.write("Contents:\n")
                try:
                    with open(file_path, 'r', errors='ignore') as f:
                        out_file.write(f.read())
                except Exception as e:
                    out_file.write(f"Error reading file: {e}")
                out_file.write("\n\n")

if __name__ == "__main__":
    # Get the current directory where the script is located
    start_directory = os.path.dirname(os.path.abspath(__file__))

    # Output file
    output_file = 'output.txt'

    # List of directories to skip
    skip_directories = [os.path.join(start_directory, 'node_modules'), os.path.join(start_directory, 'assets'), os.path.join(start_directory, 'utils'),  os.path.join(start_directory, '.git'), os.path.join(start_directory, '.expo')]

    # List of files to skip
    skip_files = ['output.txt','combined.log', 'error.log', 'package.json', 'package-lock.json', 'generated_documentation.txt', 'docker-compose.yml', 'babel.config.js']

    collect_contents(start_directory, output_file, skip_directories, skip_files)
