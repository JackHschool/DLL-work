import subprocess
import datetime
import os
import pefile

def dll_dependency_checker(executable_path, output_file):
    # Step 1: Extracting DLL names from the executable file
    dll_list = []
    try:
        pe = pefile.PE(executable_path)
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for dll in entry.imports:
                dll_list.append(dll.name.decode('utf-8'))
    except FileNotFoundError:
        print(f"Error: Executable file not found at {executable_path}")
        return None

    # Step 2: Use PowerShell to query for DLLs
    powershell_script = f"""(Get-Command '{executable_path}').DLL | ForEach-Object {{
        if (Test-Path $_ -PathType Leaf) {{
            Write-Output "$_ True"
        }} else {{
            Write-Output "$_ False"
        }}
    }}"""
    try:
        powershell_output = subprocess.check_output(["powershell", "-Command", powershell_script], text=True)
        dll_status_list = powershell_output.strip().split('\n')
    except subprocess.CalledProcessError as e:
        print("Error executing PowerShell script:", e)
        return None

    # Step 3: Generate timestamp
    timestamp = datetime.datetime.fromtimestamp(os.path.getmtime(executable_path)).strftime("%Y-%m-%d %H:%M:%S")

    # Step 4: Generate true and false lists
    true_list = []
    false_list = []
    for dll_status in dll_status_list:
        parts = dll_status.split()
        if len(parts) >= 2:
            dll_name = parts[0]
            status = parts[1]
            if status == "True":
                true_list.append(dll_name)
            else:
                false_list.append(dll_name)
        else:
            # Handle the case where there are not enough parts in the line
            print("Unexpected format:", dll_status)

    # Step 5: Write results to file
    try:
        with open(output_file, 'w') as f:
            f.write(f"Timestamp: {timestamp}\n")
            f.write("True List:\n")
            for dll in true_list:
                f.write(f"{dll}\n")
            f.write("False List:\n")
            for dll in false_list:
                f.write(f"{dll}\n")
    except Exception as e:
        print("Error writing to output file:", e)
        return None

    return {
        "True_list": true_list,
        "False_list": false_list,
        "Timestamp": timestamp
    }

# Example usage
executable_path = r"C:\Users\19735\Desktop\PE-bear.exe"
output_file = "output.txt"
result = dll_dependency_checker(executable_path, output_file)
if result:
    print("DLL Dependencies (Found):", result["True_list"])
    print("DLL Dependencies (Not Found):", result["False_list"])
    print("Timestamp:", result["Timestamp"])
