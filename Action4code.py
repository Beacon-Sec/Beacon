import pandas as pd
import os
import json


def split_into_chunks(target:str, max_length:int=950)->list:
    chunks = []
    current_chunk = ""
    for token in target:
        if len(current_chunk) + len(token) <= max_length:
            current_chunk += token
        else:
            chunks.append(current_chunk)
            current_chunk = token
    if current_chunk:
        chunks.append(current_chunk)
    return chunks

# Data Process template class
class DataProcessor:
    def __init__(self, file_path, verbose=1, seed=1):
        self.file_path = file_path
        self.verbose = verbose
        self.seed = seed
         
    def read_data(self):
        if self.verbose > 0:
            print("Reading data from file:", self.file_path)
    def get_data(self):
        if self.verbose > 0:
            print("Getting data from file:", self.file_path)


# Linux dataset
class Action_linux(DataProcessor):
    def __init__(self, file_path, verbose=1, seed=1):
        super().__init__(file_path=file_path, verbose=verbose, seed=seed)
    
    def _read_data(self):
        if self.verbose > 0:
            print("Reading data from file:", self.file_path)
        df = pd.read_csv(self.file_path)
        return df
        
    def get_data(self, slice_size:int=None)->dict:
        seed = self.seed
        codes = []; labels = []; addrs=[]
        df = self._read_data()
        rows, columns = df.shape
        if self.verbose > 0:
            print("Sum:", rows)
        if slice_size is None:
            slice_size = rows
        start_index = seed-1  
        end_index = min(start_index + slice_size, rows) if slice_size is not None else rows
        for index, row in df.iloc[start_index:end_index].iterrows():
            codes.append(row["func_before"])
            labels.append(row["vul"])
            addrs.append(row["codeLink"])
        res = {
            "codes": codes,
            "labels": labels,
            "addrs": addrs
        }
        return res

# Debian dataset
class Action_json_data(DataProcessor):
    # 初始化函数
    def __init__(self, file_path, verbose=1, seed=1):
        super().__init__(file_path=file_path, verbose=verbose, seed=seed)

    def _read_data(self):
        if self.verbose > 0:
            print("Reading data from file:", self.file_path)
        with open(self.file_path, 'r',encoding="utf-8") as json_file:
            json_data = json.load(json_file)
        return json_data
    
    def get_data(self, slice_size: int = None) -> dict:
        seed = self.seed
        codes = []
        labels = []
        addrs = []
        json_data = self._read_data()
        count = len(json_data)
        if self.verbose > 0:
            print("Sum:", count)
        if slice_size is None:
            slice_size = count
            
        start_index = seed-1
        end_index = min(start_index + slice_size, count) if slice_size is not None else count
        for i, single_data in enumerate(json_data[start_index:end_index]):
            code = single_data.get('code')
            label = single_data.get('label')            
            codes.append(code)
            labels.append(label)
            dataset = os.path.basename(os.path.split(self.file_path)[-2])

            if dataset == "debian":
                addrs.append("https://drive.google.com/drive/folders/1KuIYgFcvWUXheDhT--cBALsfy1I4utOy")
            elif dataset == "linux_kernel":
                addr =single_data.get('addr')
                addrs.append(addr)
            else:
                cve = single_data.get('cve')
                addrs.append(cve)
        res = {
            "codes": codes,
            "labels": labels,
            "addrs": addrs
        }
        return res
