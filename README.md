# ComprehendAI

An AI plugin for assisting IDA reverse analysis, which facilitates quickly summarizing the functions of code and accelerates the analysis efficiency.

## Features

### Non - blocking AI Analysis
- **Description**: This feature enables non - blocking AI analysis. While the analysis is in progress, you can continue with your work uninterrupted. Once the analysis is completed, the results will be printed in the output window.

### Blocking AI Analysis 
- **Description**: With blocking AI analysis, the results are directly annotated at the function header.

### Customizable Function Analysis Depth
- **Description**: You have the flexibility to set the depth of function analysis according to your needs. 

### Manual Interaction with AI
- **Description**: You can manually ask the AI various questions and perform any operations you prefer. 

## Usage

#### 1. Project Retrieval

First, you need to pull the project to your local machine. Open your terminal or command prompt and use the following command to clone the project repository:

```bash
git clone https://github.com/Kvancy/ComprehendAI.git
```

#### 2. File Placement

Navigate to the directory of the cloned project. Locate the `config.json` and `ComprehendAI.py` files. Then, place these two files into the `plugins` folder of IDA . 

#### 3. Configuration File Setup

Open the `config.json` file. You will see a content structure similar to the following:

```json
{
    "openai"{
        "model":"",
        "api_key": "",
        "base_url": ""
    }
}
```

Replace the content within the double - quotes with your own `api_key` and `base_url`. For example:

```json
{
    "openai"{
        "model":"",
        "api_key": "your_actual_api_key",
        "base_url": "your_actual_base_url"
    }
}
```

Save and close the `config.json` file.

#### 4. Dependencies

You need to install the following Python libraries using `pip`. You can install the `openai` library with the following command:

```py
pip install openai
```

#### 4. Launch IDA and Load the Plugin



## Example

Right - click on the disassembly window to pop up the menu and select a function.

Non - blocking AI analysis allows you to continue your work, and then the results will be printed in the output window.

![{90B305AB-0BF0-498B-8924-0E444FFCB706}](imgs/README/{90B305AB-0BF0-498B-8924-0E444FFCB706}.png)

![image-20250305102935533](imgs/README/image-20250305102935533.png)

Blocking AI analysis can directly add comments with the results at the function header, but it will block your work.

![image-20250305103259280](imgs/README/image-20250305103259280.png)

You can set the depth of function analysis by yourself. If the depth of function analysis is set too large, you need to ensure that the AI can handle such a large amount of output.

![image-20250305103453813](imgs/README/image-20250305103453813.png)

You can also manually ask the AI some questions and do whatever you like.

![image-20250305103616271](imgs/README/image-20250305103616271.png)

![image-20250305103636396](imgs/README/image-20250305103636396.png)