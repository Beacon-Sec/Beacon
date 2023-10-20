import os
import sys 
sys.path.append(os.getcwd()) 
import numpy as np
from tools.toolfuction import SplitCharacters,LoadPickleData,transpose

class SmallModel:
    def __init__(self, model_name, dataset, modelMaxlen=1000, batchSize=32, verbose=1):
        self.model_name = model_name
        self.modelMaxlen = modelMaxlen
        self.dataset = dataset
        self.batchSize = batchSize
        self.verbose = verbose

    

    
class TensorFlowSmallModel(SmallModel):
    def __init__(self, model_name, dataset, modelMaxlen=1000, verbose=1,batchSize=32):
        super().__init__(model_name, dataset, modelMaxlen = modelMaxlen, verbose = verbose,batchSize=batchSize)

    def getTokenizerPath(self):
        return os.path.join(os.getcwd(),"SmallModel","ModelSave","embedding",self.dataset,"tokenizer"+".pickle")

    def getModelPath(self):
        modelpath = os.path.join(os.getcwd(),"SmallModel","ModelSave","DeepModel",self.dataset,self.model_name)
        choosemodel = "modellack"
        valiacc = 0
        for root, dirs, files in os.walk(modelpath):
            for file in files:
                metrics = file.split("_")
                if float(metrics[2]) > valiacc:
                    valiacc = float(metrics[2])
                    choosemodel = os.path.join(root, file)
        return choosemodel
    
    

    def preprocessCode(self,code):
        
        tmp_dir = os.path.join(os.getcwd(), 'tmp')
        if not os.path.exists(tmp_dir): os.mkdir(tmp_dir)
        tmpfile = os.path.join(tmp_dir,"smallmodel.c")
        with open(tmpfile, 'w', encoding='latin1') as _f:
            _f.write(code)
        with open(tmpfile, 'r', encoding='latin1') as _f:
            lines = _f.readlines()
            file_list = []
            for line in lines:
                if line != ' ' and line != '\n': # Remove sapce and line-change characters
                    sub_line = line.split()
                    new_sub_line = []
                    for element in sub_line:
                        new_element = SplitCharacters(element)
                        new_sub_line.append(new_element)
                    new_line = ' '.join(new_sub_line)
                    file_list.append(new_line)
            new_file_list = ' '.join(file_list)
            tokens = new_file_list.split()
        return tokens

    def test(self,code,model,tokenizer):
        from tensorflow.keras.preprocessing.sequence import pad_sequences
        if self.verbose > 0:
            print("TEST START")

        test_raw=code
        model.summary()
        total_sequences = tokenizer.texts_to_sequences(test_raw)
        total_sequences = [transpose(total_sequences)]

        test_x = pad_sequences(total_sequences, maxlen=self.modelMaxlen, padding='post')
        probs = model.predict(test_x, batch_size=self.batchSize, verbose=1)
        penultimate_layer_output = self.get_output_at_penultimate_layer(model, test_x)
        # probs = model(test_x, batch_size=self.batchSize, verbose=1)
        if probs[0][0] > 0.5:
            res=1
        else:
            res=0
        distance = np.linalg.norm(probs[0][0]- 0.5)
        return res,probs[0][0],distance, penultimate_layer_output,probs
    
    def get_output_at_penultimate_layer(self, model, test_x):
        from tensorflow.keras.models import Model
        penultimate_layer_output = model.layers[-1].output
        penultimate_layer_model = Model(inputs=model.input, outputs=penultimate_layer_output)
        penultimate_layer_output = penultimate_layer_model.predict(test_x)
        return penultimate_layer_output   

    def execute(self,code:str):
        from keras.models import load_model
        

        tokens = self.preprocessCode(code)
        model_path = self.getModelPath()
        model = load_model(model_path)
        tokenizerPath = self.getTokenizerPath()
        tokenizer = LoadPickleData(tokenizerPath)

        res, prob, distance, penultimate_layer_output,probs=self.test(tokens,model,tokenizer)
       
        
        return res, prob, distance, penultimate_layer_output,probs
    
