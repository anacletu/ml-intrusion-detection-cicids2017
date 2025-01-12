# Machine Learning Intrusion Detection System for Resource-Constrained Networks (Work in Progress)

This repository contains the code and documentation for my dissertation project, which focuses on developing a Machine Learning-based Intrusion Detection System (IDS) tailored for resource-constrained networks, typical of small businesses. The project leverages the CICIDS2017 dataset for training and evaluation.

**Project Overview:**

This project aims to address the growing need for affordable and effective cybersecurity solutions for small businesses and resource-constrained environments. Traditional intrusion detection systems can be resource-intensive and expensive, making them unsuitable for these settings. This research explores the application of machine learning algorithms to detect network intrusions in such environments, focusing on anomaly-based detection to identify both known and unknown threats.

**Key Stages:**

1. **Data Preprocessing and Exploratory Data Analysis (EDA):**
   - This stage focuses on cleaning, transforming, and understanding the CICIDS2017 dataset.  The Jupyter Notebook `cicids2017-comprehensive-data-processing-for-ml.ipynb` details the steps taken to handle missing values, remove duplicates, perform feature engineering, scale numerical features, and conduct exploratory data analysis to gain insights into the dataset's characteristics. This notebook generates a scaled and preprocessed version of the dataset, optimized for various machine learning algorithms. The updated [dataset can be found on Kaggle](https://www.kaggle.com/datasets/ericanacletoribeiro/cicids2017-cleaned-and-preprocessed).

2. **Machine Learning Model Training and Evaluation:**
   -  This stage involves training and comparing the performance of different supervised and unsupervised machine learning models for anomaly detection.  Algorithms being considered include Random Forest, Support Vector Machines (SVM), Isolation Forest, and K-Means.  Evaluation metrics include accuracy, precision, recall, F1-score, ROC AUC, and resource usage (CPU time and memory).
   - A Jupyter Notebook dedicated to model training, hyperparameter tuning (using techniques such as `GridSearchCV`), and evaluation will be added soon.

3. **NIDS Prototype Development and Testing:**
   -  This stage focuses on developing a functional NIDS prototype using Python. The prototype will integrate the best-performing machine learning model identified in the previous stage and use the `scapy` library to capture and process network traffic in real time. The prototype will be deployed on a Raspberry Pi for testing in a simulated network environment using Mininet and the Atomic Red Team library for attack simulations (e.g. DoS, portscan, botnet activity).
   - The prototype's development is still a work in progress.  Code and documentation will be added to this repository as development progresses.

**Key Features:**

* Focus on resource-constrained networks (small businesses, home networks)
* Anomaly-based intrusion detection for unknown threat detection
* Comparison of supervised and unsupervised learning methods
* Efficient prototype implementation on a Raspberry Pi
* Simulated network environment for testing (Mininet, Atomic Red Team)


**Project Status:**  Work in Progress (updated as of January 2025)
