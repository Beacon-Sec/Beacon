
from Action4code import *

from Beacon import Beacon_Statics
from Chainofthought import *
from Discernment import *
from LLMmodel.GPT import GPT
from LLMmodel.Vicuna import Vicuna
from tools.Resultsaver import Results

from sklearn.metrics import classification_report, confusion_matrix
import json
import pickle as pk
import os
from SmallModel.SmallModel import TensorFlowSmallModel
import yaml

config_path = os.path.join(os.getcwd(),"config","linux_kernel.yaml")#debian.yaml FFmpeg.yaml LibTIFF.yaml
config = yaml.safe_load(open(config_path,'r',encoding="UTF-8"))

os.environ["HTTP_PROXY"] = os.environ.get('httpproxy')
os.environ["HTTPS_PROXY"] = os.environ.get('httpsproxy')

# config
LLMmodel=config.get('LLM_Func').get('LLM_model')
dataset = config.get('LLM_Func').get('Action4code').get('data_set')
size = config.get('LLM_Func').get('Action4code').get('data_size')
seed = config.get('LLM_Func').get('Action4code').get('seed')
balance = config.get('LLM_Func').get('Action4code').get('balance')
C_param = config.get('LLM_Func').get('Chain').get('algorithm')
D_param = config.get('LLM_Func').get('Discern').get('algorithm')
paras = "C_" + C_param+"_D_"+D_param+"_Size_"+str(size)
model_name = config.get('Small_Model').get('model_name')


def Classification_results(Judgements:list,Labels:list,Results)->None:
    DownLoader = Results
    print("The confusion matrix: \n")
    log = "\n"
    log += "The confusion matrix: \n"
    log += str(confusion_matrix(Labels, Judgements, labels=[0,1]))
    log += "\r\n"
    target_names = ["Non-vulnerable","Vulnerable"] #non-vulnerable->0, vulnerable->1
    print (confusion_matrix(Labels, Judgements, labels=[0,1]))  
    print ("\r\n")
    report=classification_report(Labels, Judgements, target_names=target_names)
    print (report)
    log += report
    DownLoader.savelogDData(info=log)

DownLoader = Results(hyperParas=paras, approach=LLMmodel, dataSets=dataset)

#Action
# set data path
if(dataset=="your dataset"):
    datapath =os.getcwd()+os.sep+"data"+os.sep+dataset+os.sep+"linux_data.csv"
    Linux_data = Action_linux(file_path=datapath, verbose = -1, seed=seed)
else:
    if balance>0:datapath=os.getcwd()+os.sep+"data"+os.sep+dataset+os.sep+"balance.json"
    else:datapath=os.getcwd()+os.sep+"data"+os.sep+dataset+os.sep+"test_73.json" # test_73.json test.json
    Linux_data = Action_json_data(file_path=datapath, verbose = -1, seed=seed)


codes = Linux_data.get_data(slice_size=size)["codes"]
labels = Linux_data.get_data(slice_size=size)["labels"]
addrs = Linux_data.get_data(slice_size=size)["addrs"]
deep_model = TensorFlowSmallModel(model_name=model_name, dataset=dataset)
iter = 0;judgelist = [];labellist = []


for code, label, addr in zip(codes, labels, addrs):
    iter += 1
    
    log = "\n"+ "**START**_{}".format(addr) + "\n"
    log += "\n"+"**iteration**_{}".format(iter)+"\n"

    # Beacon
    Linux_Beacon = Beacon_Statics(code, deep_model ,config)
    try:
        beacon_result = Linux_Beacon.detect_vulnerability_init()
        log += "\n" + "**Beacon**_{}".format(str(beacon_result)) + "\n"
    except Exception as e:

        print("B error",e)
        log = "**error occurs**_{}".format(str(addr)) + "\n"
        log += "-*"*80+ "\n"
        DownLoader.savelogDData(info=log)
        continue
    DownLoader.savelogDData(info=log)

    # beacon composition
    beacon_statics_vul = beacon_result['staticsVul']
    beacon_dpmodel_vul = beacon_result['smallModelVul']
    varlist = Linux_Beacon._extract_variables()

    
    mode = "normal"
    if beacon_dpmodel_vul>=0.3:mode = "abstrict"   
    if beacon_dpmodel_vul<0.3 and beacon_dpmodel_vul>=0:mode = "strict"
    if beacon_dpmodel_vul>=-0.35 and beacon_dpmodel_vul<0:mode = "ease"
    if beacon_dpmodel_vul>=-0.5 and beacon_dpmodel_vul<-0.35:mode = "abease"
        
    

    #ChainofThought
    if C_param=="detail":Linux_cot = Chainofthought(mode=mode)
    else:
        raise ValueError("C_param error: unknown parameter")
    try:
        cot_result = Linux_cot.cot_analysis(VulClass=beacon_statics_vul,code=code)
        for cot in cot_result:
            if(len(cot.split("-->")[1])<5):
                raise ValueError("empty chain error")
        log = "-"*40+"COT"+"-"*40 + "\n"
        for cot in cot_result:
            log += cot+"\n"
            log += ">"*40+"<"*40 + "\n"
    except Exception as e:
        print("C error",e)
        if (str(e) == "empty chain error"):
            log = "empty chain error**_{}".format(str(addr)) + "\n"
        else:log = "**error occurs**_{}".format(str(addr)) + "\n"
        log += "-*"*80+ "\n"
        DownLoader.savelogDData(info=log)
        continue
    DownLoader.savelogDData(info=log)


    Linux_Detect = Detector(parameters=D_param,varlist=varlist,beacon=beacon_statics_vul,mode=mode)
    try:
        discernment_result = Linux_Detect.analysis(code=code, informations=cot_result)
        log = "-"*40+"DISC"+"-"*40 + "\n"
        log += json.dumps(discernment_result)
        first_key = list(discernment_result.keys())[0]
        first_value = discernment_result[first_key] 
        judge = Linux_Detect.detect(first_value)
    except Exception as e:
        print("D error",e)
        log = "**error occurs**_{}".format(str(addr)) + "\n"
        log += "-*"*80+ "\n"
        DownLoader.savelogDData(info=log)
        continue
    DownLoader.savelogDData(info=log)


    log = "\n"+"**lab**_{}".format(label)+"\n"
    log += "\n"+"**mode**_{}_{}".format(beacon_statics_vul,mode)+"\n"
    log += "\n"+"**jud**_{}".format(judge)+"\n"
    
    judgelist.append(judge)
    labellist.append(label)
    log += "-*"*80
    DownLoader.savelogDData(info=log)
    print("{} finished".format(iter))

log  = "\nlab"+str(labellist[:size]) + "\n"
log  += "\njudge"+str(judgelist[:size]) + "\n"    
DownLoader.savelogDData(info=log)


Classification_results(judgelist,labellist,DownLoader)

log  = "\n"+"seed: {}".format(seed)   
DownLoader.savelogDData(info=log)



