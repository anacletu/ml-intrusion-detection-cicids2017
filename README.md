# Machine Learning Intrusion Detection System for Resource-Constrained Networks (Work in Progress)

This repository contains the code and documentation for my final MBA project, which focuses on developing a Machine Learning-based Intrusion Detection System (IDS) tailored for resource-constrained networks, typical of small businesses. The project leverages the CICIDS2017 dataset for training and evaluation.

**Project Overview:**

This project aims to address the growing need for affordable and effective cybersecurity solutions for small businesses and resource-constrained environments. Traditional intrusion detection systems can be resource-intensive and expensive, making them unsuitable for these settings. This research explores the application of machine learning algorithms to detect network intrusions in such environments, focusing on anomaly-based detection to identify both known and unknown threats.

**Key Stages:**

1. **Data Preprocessing and Exploratory Data Analysis (EDA):**

   This stage focuses on cleaning, transforming, and understanding the CICIDS2017 dataset. The Jupyter Notebook `cicids2017-comprehensive-data-processing-for-ml.ipynb` details the steps taken to handle missing values, remove duplicates, perform feature engineering, and conduct exploratory data analysis to gain insights into the dataset's characteristics. This notebook generates a preprocessed version of the dataset, optimized for various machine learning algorithms. The updated [dataset can be found on Kaggle](https://www.kaggle.com/datasets/ericanacletoribeiro/cicids2017-cleaned-and-preprocessed).

2. **Machine Learning Model Training and Evaluation:**

   This stage involves training and comparing the performance of different supervised and unsupervised machine learning models for anomaly detection. Algorithms being considered include Random Forest, XGBoost, KNN, Isolation Forest, and K-Means. Evaluation metrics include accuracy, precision, recall, F1-score, ROC AUC, and resource usage (CPU time and memory).

   The Jupyter Notebooks dedicated to model training, hyperparameter tuning (using techniques such as `RandomSearchCV`), and testing are:

   1. Supervised: `cicids2017-ml-models-comparison-supervised.ipynb`.
   2. Unsupervised: `cicids2017-ml-models-comparison-unsupervised.ipynb`.

   And can also be found on Kaggle [here](https://www.kaggle.com/code/ericanacletoribeiro/cicids2017-ml-models-comparison-supervised) and [here](https://www.kaggle.com/code/ericanacletoribeiro/cicids2017-ml-models-comparison-unsupervised).

3. **NIDS Prototype Development and Testing:**

   This stage focuses on developing a functional NIDS prototype using Python. The prototype integrates the best-performing machine learning model identified in the previous stage (XGBoost) and use the `scapy` library to capture and process network traffic in real time.

   - The `NetworkAnomalyDetector` class handles feature extraction, anomaly detection, and alert generation. The `NetworkAnomalyGUI` provides a user interface for monitoring and controlling the NIDS. The prototype is designed for deployment on a resource-constrained device.

   The prototype is being tested on a Raspberry Pi 5 in a simulated network environment using the Atomic Red Team framework for attack simulations (e.g. DoS, portscan, botnet activity). Results will be available soon.

**Key Features:**

- **Resource-Constrained Focus:** Designed for low-power devices like the Raspberry Pi, making it suitable for small businesses and home networks.
- **Anomaly-Based Detection:** Detects both known and unknown threats by identifying deviations from normal network behavior.
- **XGBoost Algorithm:** Leverages the efficient and high-performing XGBoost algorithm for anomaly detection.
- **Real-time Traffic Analysis:** Analyzes network traffic in real-time using `scapy`.
- **User Interface:** Provides a graphical user interface for monitoring and managing alerts.
- **Simulated Test Environment:** Uses Atomic Red Team for realistic attack simulations.
- **Structured Logging and Reporting:** Logs alerts in JSON format and includes a reporting mechanism to generate performance statistics.

## Getting Started

TDB

## Future Work

TDB

**Project Status:** Work in Progress (updated as of March 2025)
