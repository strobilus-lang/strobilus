import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

# Load data from the CSVs
df1_raw = pd.read_csv('./results/cedar-local-state.csv')
df2_raw = pd.read_csv('./results/cedar-upsert.csv')
df3_raw = pd.read_csv('./results/strobilus.csv')

def remove_outliers_iqr(df):
    df_no_outliers = df.copy()
    for column in df.columns:
        Q1 = df[column].quantile(0.25)
        Q3 = df[column].quantile(0.75)
        IQR = Q3 - Q1
        lower_bound = Q1 - 1.5 * IQR
        upper_bound = Q3 + 1.5 * IQR

        df_no_outliers[column] = df_no_outliers[column].apply(
            lambda x: x if (x >= lower_bound) and (x <= upper_bound) else np.nan
        )
    return df_no_outliers

df1 = remove_outliers_iqr(df1_raw)
df2 = remove_outliers_iqr(df2_raw)
df3 = remove_outliers_iqr(df3_raw)

# Calculate mean and standard deviation for each column
mean1 = df1.mean() / 1000.0
std1 = df1.std() / 1000.0

mean2 = df2.mean() / 1000.0
std2 = df2.std() / 1000.0

mean3 = df3.mean() / 1000.0
std3 = df3.std() / 1000.0

# Plot the three series
plt.figure(figsize=(12, 8))

x_points = np.arange(len(mean1))

plt.plot(x_points, mean1, label='Cedar-local-state')
plt.fill_between(x_points, mean1 - std1, mean1 + std1, alpha=0.2)

plt.plot(x_points, mean2, label='Cedar-upsert')
plt.fill_between(x_points, mean2 - std2, mean2 + std2, alpha=0.2)

plt.plot(x_points, mean3, label='Strobilus-counter')
plt.fill_between(x_points, mean3 - std3, mean3 + std3, alpha=0.2)
    
plt.xlabel('Request number')
plt.ylabel(r'Time ($\mu s$)')
plt.title('Strobilus vs Cedar comparison')
plt.legend()
plt.xticks(x_points, x_points + 1)
plt.ylim(ymin=0)
plt.grid(True)

plt.savefig("rq1_plot.png")
