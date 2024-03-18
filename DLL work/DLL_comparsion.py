import os
import datetime

def dll_comparison(executable_path, date_d, past_lists_file=None):
    # Step 1: Gather DLLs at Date d using DLL Dependency Checker
    result_d = dll_dependency_checker(executable_path, date_d, past_lists_file)
    false_d = set(result_d["False_list"])
    true_d = set(result_d["True_list"])

    # Step 2: Gather Current DLLs using DLL Dependency Checker
    result_now = dll_dependency_checker(executable_path)
    false_now = set(result_now["False_list"])
    true_now = set(result_now["True_list"])

    # Step 3: Output Comparison Results
    comparison_results = {
        "False_d_and_True_now": list(false_d.intersection(true_now)),
    }

    return comparison_results

def dll_dependency_checker(executable_path, date=None, past_lists_file=None):
    # Step 1: DLL gathering from a.exe
    with open(executable_path, 'r') as exe_file:
        dll_list = [line.strip() for line in exe_file.readlines() if line.strip().endswith('.dll')]

    # Step 2: DLL Categorization based on existence
    true_list = []
    false_list = []

    for dll in dll_list:
        if past_lists_file is not None:
            with open(past_lists_file, 'r') as f:
                past_lists = f.readlines()
                past_false_list = [line.strip() for line in past_lists[0].split(',') if line.strip()]
                past_true_list = [line.strip() for line in past_lists[1].split(',') if line.strip()]
            if dll in past_false_list:
                false_list.append(dll)
            elif dll in past_true_list:
                true_list.append(dll)
        elif date is not None:
            # Check DLL existence at specified date
            dll_path = os.path.join(os.path.dirname(executable_path), dll)
            if os.path.exists(dll_path):
                dll_modified_time = datetime.datetime.fromtimestamp(os.path.getmtime(dll_path))
                if dll_modified_time <= date:
                    true_list.append(dll)
                else:
                    false_list.append(dll)
            else:
                false_list.append(dll)
        else:
            # Check current DLL existence
            dll_path = os.path.join(os.path.dirname(executable_path), dll)
            if os.path.exists(dll_path):
                true_list.append(dll)
            else:
                false_list.append(dll)

    # Step 3: Output the results
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return {
        "False_list": false_list,
        "True_list": true_list,
        "Timestamp": timestamp
    }

# Example usage
executable_path = "path_to_your_executable/a.exe"  # Replace with the actual path
date_d = datetime.datetime(2024, 1, 1)  # Replace with the specific date
past_lists_file = "path_to_your_past_lists_file.txt"  # Replace with the actual path
comparison_result = dll_comparison(executable_path, date_d, past_lists_file)
print("DLLs that were false at d and true now:", comparison_result["False_d_and_True_now"])
