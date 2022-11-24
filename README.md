# IAM Policy Analyser

[TOC]

## Description

This is the tool developed as my final project in University. I study Computer Engineering in CEFET-MG, in Brazil.

This tool analyses and classifies AWS IAM Policies, according to the severity of its actions. It shows you the critical actions included in the policy, and the definitions of each action. That way, you can define which actions are a risk for the business, and remove them before granting the permission to an IAM Role or IAM User.


## Pre-Requisites
- Terminal with Bash;
- Python version 3.10.6 or above;
- Python Libraries (shown in the next section);


## Install Dependencies
```bash
# install Python
sudo apt install python3

# Install Python pip
sudo apt install python3-pip

# Install necessary libraries
pip3 install requests pandas bs4 datetime numpy
```

## How to use
1. Clone the repository to your computer or download the ZIP file by clicking [HERE](https://github.com/TulioBittar/tcc-iam-policy-analyser/archive/refs/heads/main.zip).
2. Save the IAM Policy you want to analyse in the directory below:

```bash
tcc-iam-policy-analyser/policy-analyser/analyse-policy/
```

3. Execute IAM Policy Analyser:

```bash
# Navigate to the directory 'policy-analyser'
cd ~/tcc-iam-policy-analyser/policy-analyser/

# Execute the analyser
python3 iam-policy-analyser.py
```

4. Insert the file name of the IAM Policy you wish to analyse, including the extension, and press ENTER:

```bash
Enter policy file name (with extension): policy-example.json
```

5. The scan will show the findings during the execution.
6. After execution is done, you can find the complete result of the scan in the directory below:

```bash
tcc-iam-policy-analyser/policy-analyser/history/<TIMESTAMP>/
```

Done! Enjoy and scan any IAM Policy you want.

More improvements are yet to come.
Thank you.


## Information About The Author

### **Túlio Bittar**

- [Email](<mailto:tulio.bittar@outlook.com>)
- [Linkedin](https://www.linkedin.com/in/tulio-bittar/)
- [Github](https://github.com/TulioBittar)

### Grade and Work details:
- Graduated in Computer Engineering at [CEFET-MG](https://www.cefetmg.br/)
- Cloud Security Analyst at [Inter](https://www.bancointer.com.br/)
- AWS Certified Solutions Architect Associate
