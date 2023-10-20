# LLM4SEC - Linux Kernel Vulnerability Detection with Two Different Large Language Models

The overall framework is divided into four parts:

## A: Action4code Data Processing (Including Static Analysis Module)

## B: Beacon - Generation of Initial Guidance for Preliminary Detection

## C: Chain of Thought - Utilizing Knowledge Base for Chain of Thought Generation

## D: Discernment - Integrated Result Generation Using Large Language Deep Thought Pool

## Main: Call and Process Automatically

|- codesensor: Static Processing Tool

|- data: Dataset

|- LLMmodel: Large Language Model Invocation

|- result: Result Storage

|- tmp: Process Redundancy

|- tools: Utility Classes

|- SmallModel: Train and test small models

|- config: Configuration


A, B, C, D, M as described in the framework above

# Environment Configuration
Start the virtual environment (customize it according to your own virtual environment).
To use the code, you must set the environment variable 'openaikey.'
The proxy settings are also required if necessary:
Set 'HTTP_PROXY' and 'HTTPS_PROXY.'
These configurations should be configured in files under LLMmodel.
