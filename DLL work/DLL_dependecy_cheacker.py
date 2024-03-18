import subprocess
import datetime
import os
import pefile

def dll_dependency_checker(executable_path):
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
    except subprocess.CalledProcessError:
        dll_status_list = []

    # Step 3: Generate timestamp
    timestamp = datetime.datetime.fromtimestamp(os.path.getmtime(executable_path)).strftime("%Y-%m-%d %H:%M:%S")

    # Step 4: Generate true and false lists
    true_list = []
    false_list = []
    for dll_status in dll_status_list:
        dll_name, status = dll_status.split()
        if status == "True":
            true_list.append(dll_name)
        else:
            false_list.append(dll_name)

    # Step 5: Generate result dictionary
    result = {
        "True_list": true_list,
        "False_list": false_list,
        "Timestamp": timestamp
    }

    return result

# Example usage
executable_path = "path_to_your_executable/a.exe"
result = dll_dependency_checker(executable_path)
if result:
    print("DLL Dependencies (Found):", result["True_list"])
    print("DLL Dependencies (Not Found):", result["False_list"])
    print("Timestamp:", result["Timestamp"])
