import tkinter as tk
from tkinter import messagebox
import matplotlib.pyplot as plt
import csv

# BMI calculation
def calculate_bmi(weight, height):
    return weight / (height ** 2)

# Classify BMI
def classify_bmi(bmi):
    if bmi < 18.5:
        return "Underweight"
    elif 18.5 <= bmi < 24.9:
        return "Normal weight"
    elif 25 <= bmi < 29.9:
        return "Overweight"
    else:
        return "Obesity"

# Save data to CSV
def save_data(weight, height, bmi, category):
    with open("bmi_data.csv", mode="a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([weight, height, bmi, category])

# Show BMI Result
def show_bmi_result():
    try:
        weight = float(weight_entry.get())
        height = float(height_entry.get())
        
        bmi = calculate_bmi(weight, height)
        category = classify_bmi(bmi)
        
        result_label.config(text=f"BMI: {bmi:.2f}\nCategory: {category}")
        
        # Save data
        save_data(weight, height, bmi, category)
    
    except ValueError:
        messagebox.showerror("Invalid Input", "Please enter valid numerical values.")

# Plot BMI Trends
def plot_bmi_trends():
    weights, heights, bmis, categories = [], [], [], []
    
    try:
        with open("bmi_data.csv", mode="r") as file:
            reader = csv.reader(file)
            for row in reader:
                weights.append(float(row[0]))
                heights.append(float(row[1]))
                bmis.append(float(row[2]))
                categories.append(row[3])
        
        plt.plot(bmis, label="BMI Over Time")
        plt.xlabel("Entries")
        plt.ylabel("BMI")
        plt.title("BMI Trend Analysis")
        plt.legend()
        plt.show()
    
    except FileNotFoundError:
        messagebox.showinfo("No Data", "No BMI data available to plot.")

# GUI Setup
root = tk.Tk()
root.title("BMI Calculator")

# Weight Input
tk.Label(root, text="Enter weight (kg):").pack()
weight_entry = tk.Entry(root)
weight_entry.pack()

# Height Input
tk.Label(root, text="Enter height (m):").pack()
height_entry = tk.Entry(root)
height_entry.pack()

# Calculate Button
calc_button = tk.Button(root, text="Calculate BMI", command=show_bmi_result)
calc_button.pack()

# Result Label
result_label = tk.Label(root, text="BMI: \nCategory: ", font=("Helvetica", 14))
result_label.pack()

# Plot Button
plot_button = tk.Button(root, text="Show BMI Trends", command=plot_bmi_trends)
plot_button.pack()

# Run the application
root.mainloop()
