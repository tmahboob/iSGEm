######## Contributor: Dr. Tahira Mahboob, NetLab, University of Glasgow, UK #######
####### Code: Performance monitoring on machine learning inference engine ##############


import pandas as pd
from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score

# Function to calculate the various metrics
def calculate_metrics(y_true, y_pred):
    # True positives, false positives, true negatives, false negatives
    tp = ((y_true == 1) & (y_pred == 1)).sum()
    fp = ((y_true == 0) & (y_pred == 1)).sum()
    tn = ((y_true == 0) & (y_pred == 0)).sum()
    fn = ((y_true == 1) & (y_pred == 0)).sum()

    # Calculating various metrics
    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred)
    recall = recall_score(y_true, y_pred)
    f1 = f1_score(y_true, y_pred)
    false_alarm_rate = fp / (fp + tn) if (fp + tn) != 0 else 0
    true_alarm_rate = tp / (tp + fn) if (tp + fn) != 0 else 0
    true_positive_rate = tp / (tp + fn) if (tp + fn) != 0 else 0
    false_positive_rate = fp / (fp + tn) if (fp + tn) != 0 else 0
    auc = (true_positive_rate+ (1 - false_positive_rate))/2
    

    # Returning the metrics as a dictionary
    return {
        'Accuracy': accuracy,
        'Precision': precision,
        'Recall': recall,
        'F1 Score': f1,
        'False Alarm Rate': false_alarm_rate,
        'True Alarm Rate': true_alarm_rate,
        'True Positive Rate': true_positive_rate,
        'False Positive Rate': false_positive_rate,
        'ROC':auc
    }
    

# Read the CSV file
#df = pd.read_csv('results-8features.csv')  # Replace with your actual file path
#df = pd.read_csv('result_RF.csv')  # Replace with your actual file path
df = pd.read_csv('metrics2.csv')  # Replace with your actual file path

# Assuming the columns 'y_true' and 'y_pred' are the actual and predicted values
y_true = df['y_true']  # Replace with the name of the actual column in your CSV
y_pred = df['y_pred']  # Replace with the name of the predicted column in your CSV

# Calculate metrics
metrics = calculate_metrics(y_true, y_pred)

# Convert the metrics to a DataFrame
metrics_df = pd.DataFrame([metrics])

# Store the metrics into a new CSV
metrics_df.to_csv('metrics_outpu78.csv', index=False)

print(f"Metrics stored in 'metrics_output78.csv': \n{metrics_df}")
