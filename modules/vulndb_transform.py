import pandas as pd
import os

def read_vulndb_excel(file_path):
    if not os.path.exists(file_path):
        print(f"The vulndb file {file_path} does not exist.")
        quit()
    try:
        # Read the Excel file
        df = pd.read_excel(file_path, header=None)
    except Exception as e:
        raise IOError(f"An error occurred while trying to read the vulndb file {file_path}: {e}")
        quit()
    
    # Search for the columns "Vulnerability ID" and "Container" within the first 50 rows
    for i in range(50):
        if "Vulnerability ID" in df.iloc[i].values and "Container" in df.iloc[i].values:
            vuln_id_col = df.iloc[i].values.tolist().index("Vulnerability ID")
            container_col = df.iloc[i].values.tolist().index("Container")
            break
    else:
        raise ValueError("Required columns 'Vulnerability ID' and 'Container' not found within the first 50 rows of vulndb file")
    
    # Read the data again with the correct header
    df = pd.read_excel(file_path, header=i)
    
    # Filter out rows where the "Container" column is null
    df_filtered = df[df["Container"].notnull()]
    
    # Convert the filtered DataFrame into a dictionary
    data_dict = df_filtered[["Vulnerability ID", "Container"]].to_dict(orient="records")
    
    return data_dict