import os
from collections import Counter
from LLMmodel.GPT import GPT
from gensim.similarities import Similarity
from gensim import corpora, models
from nltk import word_tokenize
from nltk.corpus import stopwords



flawfinder_mapping = {
    "CWE-20":['improper input validation', 'improper syntactic validation', 'path traversal', 'injection', 'format string injection', 'command injection', 'code injection'],
    "CWE-22":['improper input validation', 'improper syntactic validation', 'path traversal', 'injection', 'command injection', 'code injection'],
    "CWE-78":['buffer overflow', 'pointer issues', 'null pointer dereference', 'pointer allocate/free issue', 'pointer range limitation'],
    "CWE-119":['Out-of-Bounds Access','improper exception handling', 'improper resource control', 'resource exposure'],
    "CWE-120":['improper input validation', 'improper syntactic validation', 'path traversal', 'injection', 'format string injection', 'command injection', 'code injection'],
    "CWE-126":['buffer overflow'],
    "CWE-134":['improper input validation', 'improper syntactic validation'],
    "CWE-190":['numerical resource limitation','wrap-around error'],
    "CWE-250":['access control', 'improper authorization', 'improper authentication'],
    "CWE-327":["broken cryptographic algorithm"],
    "CWE-362":["race condition"],
    "CWE-676":["protection mechanism failure"],
    "CWE-732":['access control', 'improper authorization'],
    "CWE-785":['path traversal', 'access control'],
    "CWE-807":['improper input validation','injection'],
    "CWE-829":['insufficiently trustworthy component',"access control","coding standards"],
    "CWE-119!/CWE-120":['improper input validation', 'improper syntactic validation', 'path traversal', 'injection', 'format string injection', 'command injection', 'code injection']
}

cppcheck_error_types = ['access control', 'improper authorization', 'improper authentication', 'protection mechanism failure', 
    'missing sensitive data encryption', 'broken cryptographic algorithm', 'coding standards', 
    'prohibited code usage', 'insufficiently trustworthy component', 'time-related error', 
    'improper exception handling', 'improper resource control', 'resource exposure', 
    'uncontrolled resource consumption', 'wrong phase resource operation', 
    'insufficient control flow management', 'race condition', 'excessive iteration', 
    'incorrect behavior order', 'out-of-bounds access', 'buffer overflow', 
    'unlimited resource allocation', 'pointer issues', 'null pointer dereference', 'pointer allocate/free issue', 
    'pointer range limitation', 'numerical resource limitation', 'wrap-around error', 'incorrect integer bit shift', 
    'insufficient real number precision', 'pointer calculation error', 'incorrect string length calculation', 
    'off-by-one error', 'division by zero', 'encoding error', 'improper input validation', 
    'improper syntactic validation', 'path traversal', 'injection', 'format string injection', 
    'command injection', 'code injection', 'inconsistent unverified', 'improper special elements']
# Construct a corpus of fine-grained error types to facilitate text similarity comparison when normalizing cppcheck error messages later.
corpora_documents = [ text.split(' ') for text in cppcheck_error_types]
dictionary = corpora.Dictionary(corpora_documents)
corpus = [dictionary.doc2bow(text) for text in corpora_documents]
tfidf = models.TfidfModel(corpus)
corpus_tfidf = tfidf[corpus]
similarity = Similarity('Similarity-tfidf-index', corpus_tfidf, num_features=len(dictionary)) 
similarity.num_best = 1

# Fine-grained error types -> Mapping table of coarse-grained error types, equivalent to the inversion of Taxonomy_tree4vul key-value pairs
coarse_grained_cppcheck_error_types_map = {
    'improper authorization': 'access control', 'improper authentication': 'access control',
    'missing sensitive data encryption': 'protection mechanism failure', 'broken cryptographic algorithm': 'protection mechanism failure',
    'prohibited code usage': 'coding standards', 'insufficiently trustworthy component': 'coding standards',
    'time-related Error': 'time-related Error',
    'improper exception handling': 'improper exception handling',
    'resource exposure': 'improper resource control', 'uncontrolled resource consumption': 'improper resource control', 'wrong phase resource operation': 'improper resource control',
    'race condition': 'insufficient control flow management', 'excessive iteration': 'insufficient control flow management', 'wrong phase resource operation': 'insufficient control flow management',
    'out-of-bounds access': 'uncontrolled resource consumption', 'buffer overflow': 'uncontrolled resource consumption', 'unlimited resource allocation': 'uncontrolled resource consumption',
    'null pointer dereference': 'pointer issues', 'pointer allocate/free issue': 'pointer issues', 'pointer range limitation': 'pointer issues',
    'wrap-around error': 'numerical resource limitation', 'incorrect integer bit shift': 'numerical resource limitation', 'insufficient real number precision': 'numerical resource limitation',
    'incorrect string length calculation': 'incorrect string length calculation',
    'pointer calculation error': 'pointer calculation error',
    'off-by-one error': 'off-by-one error',
    'division by zero': 'division by zero',
    'encoding error': 'encoding error',
    'improper input validation': 'improper data validation', 'improper syntactic validation': 'improper data validation', 'path traversal': 'improper data validation',
    'format string injection': 'injection', 'command injection': 'injection', 'code injection': 'injection',
    'inconsistent unverified': 'inconsistent unverified',
    'improper special elements': 'improper special elements',
    'unknown': 'unknown'
}
class Beacon:
    """
    A template class for detecting vulnerabilities in code.
    """
    def __init__(self, code, config):
        self.code = code
        self.config = config
    
    def detect_vulnerability_init(self):
        
        # TODO: Implement remote code execution detection logic.
        # Return True if remote code execution vulnerability is detected, otherwise False
        pass



class Beacon_Statics(Beacon):
    """
    A class for detecting vulnerabilities in Linux code with variable detection.
    """
    def __init__(self, code, DPM, config, codesensor_path:str="./codesensor/CodeSensor.jar",LLM = GPT()):
        super().__init__(code, config)
        self.sensorfile = codesensor_path
        current_dir = os.getcwd()
        # Check if tmp folder exists
        tmp_dir = os.path.join(current_dir, 'tmp')
        if not os.path.exists(tmp_dir): os.mkdir(tmp_dir)
        operfile = os.path.join(tmp_dir,"covar.c")
        with open(operfile, 'w') as f:
            f.write(self.code) 
        self.ast_result = os.path.join(tmp_dir,"ast.txt")
        os.system("java -jar "+self.sensorfile+" {} > {}".format(operfile,self.ast_result))
        self.LLM = LLM
        self.DPM = DPM
        self._weights = [7,6,3,2]
        self._beacon_results = {}
        self.config = config

    # Use parent-child relationship to process Beacon results
    def _relationship_taxonomy(self,beacon_results:list)->list:
        Taxonomy_tree4vul={
            'access control':['improper authorization', 'improper authentication'],
            'protection mechanism failure':['missing sensitive data encryption', 'broken cryptographic algorithm'],
            'coding standards':['prohibited code usage', 'insufficiently trustworthy component'],
            'time-related Error':[],
            'improper exception handling':[],
            'improper resource control':['resource exposure', 'uncontrolled resource consumption', 'wrong phase resource operation'],
            'insufficient control flow management':['race condition', 'excessive iteration', 'incorrect behavior order'],
            'uncontrolled resource consumption':['out-of-bounds access', 'buffer overflow', 'unlimited resource allocation'],
            'pointer issues':['null pointer dereference', 'pointer allocate/free issue',  'pointer range limitation'],
            'numerical resource limitation':['wrap-around error', 'incorrect integer bit shift', 'insufficient real number precision'],
            'incorrect string length calculation':[],
            'pointer calculation error':[],
            'off-by-one error':[],
            'division by zero':[],
            'encoding error':[],
            'improper data validation':['improper input validation', 'improper syntactic validation', 'path traversal'],
            'injection':['format string injection', 'command injection', 'code injection'],
            'inconsistent unverified':[],
            'improper special elements':[],
            'unknown':[]
        }
        updated_list = beacon_results.copy()
        for parent, children in Taxonomy_tree4vul.items():
            if parent in updated_list and any(child in updated_list for child in children):
                updated_list.remove(parent)
        return updated_list

    # Parse cppcheck results
    def parse_cppcheck_output(self,output):
        lines = output.split('\n')        
        parsed = []       
        for line in lines:
            parsed_line = line.split(':', 3)[-1].strip()
            if "error:" in parsed_line:
                parsed.append(parsed_line.split("error:")[-1].strip())
            elif "warning:" in parsed_line:
                parsed.append(parsed_line.split("warning:")[-1].strip())
        return parsed 

    #Extract variables
    def _extract_variables(self):
        variables=[]
        with open(self.ast_result,'r', encoding='latin1') as fp:
            lines = fp.readlines()
            for line in lines:
                oplist = line.split("\t")
                if(oplist[0]=="decl"):
                    variables.append(oplist[-1].replace("\n",""))
                if(oplist[0]=="arg"):
                    variables.append(oplist[-1].replace("\n",""))
        result = []
        for var in variables:
            if not var.isdigit():
                result.append(var)
        return result
    
    # Parse buffer category
    def _has_string_functions(self,function_list):
        string_functions = ['strcpy', 'strncpy', 'strcat', 'strncat', 'gets', 'fgets', 'scanf', 'sscanf']
        for func in function_list:
            if func in string_functions:
                return True
        return False

    def _has_memory_functions(self,function_list):
        memory_functions = ['memcpy', 'memmove']
        for func in function_list:
            if func in memory_functions:
                return True
        return False

    def _has_format_functions(self,function_list):
        format_functions = ['sprintf', 'snprintf']
        for func in function_list:
            if func in format_functions:
                return True
        return False
    
    #Extract function calls
    def _extract_buffer_sink(self)->bool:
        functions = []  
        with open(self.ast_result,'r', encoding='latin1') as fp:
            lines = fp.readlines()
            for line in lines:
                oplist = line.split("\t")
                if(oplist[0]=="call"):
                    functions.append(oplist[-1].replace("\n",""))
        if self._has_string_functions(functions):
            return True
        if self._has_memory_functions(functions):
            return True
        if self._has_format_functions(functions):
            return True
        else:
            return False

    # Update record dictionary
    def _update_dict(self, dictionary, key , weight):
        if key in dictionary:
            dictionary[key] += weight
        else:
            dictionary[key] = weight
        return dictionary


    def _clean_Beacon(self, lst:list)->list:
        updated_list = []
        for item in lst:
            updated_item = item.replace("vulnerability classes: ", "")
            updated_list.append(updated_item)
        return updated_list
    
    # Standardize cppcheck vulnerability error messages
    def _normalized_cppcheck_error_types(self, raw_error_info, granularity=1):
        if('syntaxerror' in raw_error_info.lower()):
            return 'unknown'
        cutwords1 = word_tokenize(raw_error_info.lower()) 
        interpunctuations = [',', '.', ':', ';', '?', '(', ')', '[', ']', '&', '!', '*', '@', '#', '$', '%', '\'', '\"', '`']
        cutwords2 = [word for word in cutwords1 if word not in interpunctuations]
        stops = set(stopwords.words("english"))
        cutwords3 = [word for word in cutwords2 if word not in stops]
        

        test_corpus_1 = dictionary.doc2bow(cutwords3)
        similarity.num_best = 1
        result = similarity[test_corpus_1]
        res = cppcheck_error_types[result[0][0]] if len(result) > 0 else 'unknown'
        # When granularity == 1, fine-grained errors should be mapped to coarse-grained errors.
        return res if granularity == 0 else coarse_grained_cppcheck_error_types_map.get(res)

    #Four assembled Beacon algorithms
    def _beacon_buffer_sink(self):
        if(self._extract_buffer_sink()):
            self._update_dict(self._beacon_results,"Buffer Overflow".lower(), self._weights[0])
            self._update_dict(self._beacon_results,"Out-of-Bounds Access".lower(), self._weights[0])

    def _beacon_flawsfinder(self):
        current_dir = os.getcwd()
        # Check if the tmp folder exists
        tmp_dir = os.path.join(current_dir, 'tmp')
        if not os.path.exists(tmp_dir): os.mkdir(tmp_dir)
        operfile = os.path.join(tmp_dir,"covar.c")
        resultfile = os.path.join(tmp_dir,"statics_result1.csv")
        opstr = "flawfinder --csv >{} {}".format(resultfile,operfile)
        os.system(opstr)
        import pandas as pd
        df = pd.read_csv(resultfile)
        flawfinder_result = df['CWEs']
        cwe_data =flawfinder_result.tolist()
        recog_info = []
        for cwe_info in cwe_data:
            recog_info += flawfinder_mapping[cwe_info]           
        set_recog_info = set(recog_info)   
        list_recog_info = list(set_recog_info) 
        for answer in list_recog_info:
            self._update_dict(self._beacon_results,answer.lower(), self._weights[1]) 

    # granularity = 0 is fine-grained, >= 1 is coarse-grained, the default is coarse-grained
    def _beacon_cppcheck(self, granularity = 1):
        import subprocess
        current_dir = os.getcwd()
        # Check if the tmp folder exists
        tmp_dir = os.path.join(current_dir, 'tmp')
        if not os.path.exists(tmp_dir): os.mkdir(tmp_dir)
        operfile = os.path.join(tmp_dir,"covar.c")
        # cppcheck command and parameters
        cmd = ['cppcheck', '--enable=warning', '--error-exitcode=1', operfile]
        # Run cppcheck
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        info = stderr.decode('utf-8', 'ignore')
        
        parsed_errors_and_warnings = self.parse_cppcheck_output(info)
        parsed_errors_and_warnings = list(set(parsed_errors_and_warnings))
        if len(info) > 0:

            list_recog_info = parsed_errors_and_warnings
            for answer in list_recog_info:
                self._update_dict(self._beacon_results, self._normalized_cppcheck_error_types(answer, granularity), self._weights[2])

    def _beacon_rats(self, granularity = 1):
        import subprocess
        current_dir = os.getcwd()
        # Check if the tmp folder exists
        tmp_dir = os.path.join(current_dir, 'tmp')
        if not os.path.exists(tmp_dir): os.mkdir(tmp_dir)
        operfile = os.path.join(tmp_dir,"covar.c")
        # rats commands and parameters
        cmd = ['rats', operfile]
        # run rats
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        info = stdout.decode('utf-8', 'ignore')
        list_recog_info = self.parse_rats_output(info)
        for answer in list_recog_info:
            self._update_dict(self._beacon_results, self._normalized_cppcheck_error_types(answer.lower(), granularity), self._weights[2])

    def _beacon_var_potential(self,sort_var_num:int=3):
        variables = self._extract_variables()
        # Determine the importance of variables (currently more than one is important)
        from collections import Counter
        counted = Counter(variables)
        # Use the sorted function to sort the results
        sorted_counted = sorted(counted.items(), key=lambda x: x[1], reverse=True)
        #Specify the list of variables to be operated on
        operating_var_list = []
        for item, count in sorted_counted[:sort_var_num]:
            operating_var_list.append(item)
        fewShotTemplate = f"""
                the variables {str(operating_var_list)} is one of the variables in a function
                What potential vulnerabilities does this variable introduce in this function.
                You SHOULD USE the FOLLOWING TECHNICAL TERMS TO describe the vulnerability. If the class is not covered by THESE terms, you can describe it yourself.
                'access control', 'improper authorization', 'improper authentication', 'protection mechanism failure', 
                 'missing sensitive data encryption', 'broken cryptographic algorithm', 'coding standards', 
                 'prohibited code usage', 'insufficiently trustworthy component', 'time-related error', 
                 'improper exception handling', 'improper resource control', 'resource exposure', 
                 'uncontrolled resource consumption', 'wrong phase resource operation', 
                 'insufficient control flow management', 'race condition', 'excessive iteration', 
                 'incorrect behavior order', 'out-of-bounds access', 'buffer overflow', 
                 'unlimited resource allocation', 'pointer issues', 'null pointer dereference', 'pointer allocate/free issue', 
                 'pointer range limitation', 'numerical resource limitation', 'wrap-around error', 'incorrect integer bit shift', 
                 'insufficient real number precision', 'pointer calculation error', 'incorrect string length calculation', 
                 'off-by-one error', 'division by zero', 'encoding error', 'improper input validation', 
                 'improper syntactic validation', 'path traversal', 'injection', 'format string injection', 
                 'command injection', 'code injection', 'inconsistent unverified', 'improper special elements', 'unknown' 
                Please indicate the possible vulnerability types in descending order of likelihood.
                give your answers only about Vulnerability classes in the following list format example without any details.
                Vulnerability classes1, Vulnerability classes2, Vulnerability classes3, ...
            """
        answers = self.LLM.get_completion(fewShotTemplate).split(", ")
        
        #Add the result to the beacon judgment list
        for answer in answers:
            self._update_dict(self._beacon_results,answer.lower(), self._weights[2]) 
    
    def _beacon_small_model(self)->int:
        # Feedback signed distance
        smallmodel = self.DPM
        res, prob, distance, penultimate_layer_output = smallmodel.execute(self.code)
        if res == 1:
            smallModelVul = distance
        elif res == 0:
            smallModelVul = -distance
        else:
            print("No small deep model found")
            smallModelVul = -1
        
        return smallModelVul

    
    
    def detect_vulnerability_init(self,K:int=2):
        """
        Detects remote code execution vulnerability in Linux code with variable detection.
        """
      

        autoflag = 0
        # flawsfinder
        lenthbeacon = len(self._beacon_results)
        self._beacon_flawsfinder() 
        if(len(self._beacon_results)>lenthbeacon):
            autoflag = 1
            print("flawfinder:",self._beacon_results)
        
        lenthbeacon = len(self._beacon_results)

        # cppcheck
        self._beacon_cppcheck()
        if(len(self._beacon_results)>lenthbeacon):
            autoflag = 1
            print("cppcheck:",self._beacon_results)

        # lenthbeacon = len(self._beacon_results)
        # # rats
        # self._beacon_rats()
        # if(len(self._beacon_results)>lenthbeacon):
        #     autoflag = 1
        #     print("rats:",self._beacon_results)
        

        lenthbeacon = len(self._beacon_results)
        # buffer overflow
        self._beacon_buffer_sink()
        if(len(self._beacon_results)>lenthbeacon):
            autoflag = 1
            print("bufferreg:",self._beacon_results)

        # variable-based identification
        # self._beacon_var_potential()
        
        
        sinkVul = sorted(self._beacon_results, key=self._beacon_results.get, reverse=True)
        sinkVul = self._relationship_taxonomy(sinkVul)
        sinkVul = self._clean_Beacon(sinkVul)
        if(autoflag == 0):
            cleanSinkVul = sinkVul[:1]
        else:
            cleanSinkVul = sinkVul
          
        # Return code execution vulnerability classify
        # if not recognized 
        if(autoflag == 0 and len(cleanSinkVul)<K and "auto_prompts" not in cleanSinkVul):
            cleanSinkVul.append("auto_prompts")
        
        if self.config.get('Small_Model') is not None:
            try:
                smallModelVul = self._beacon_small_model()
            except Exception as e:
                print("No small deep model found")
                print(e)
                smallModelVul = -1
        else:
            smallModelVul = -1
        res = {
            "staticsVul": cleanSinkVul[:K],
            "smallModelVul": smallModelVul
        }
        return res
