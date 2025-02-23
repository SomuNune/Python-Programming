import requests
import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
from geopy.geocoders import Nominatim
import datetime

API_KEY = "156c34d19bcdf5100d28a239d6810e78"
BASE_URL = "https://api.openweathermap.org/data/2.5/weather"
FORECAST_URL = "https://api.openweathermap.org/data/2.5/onecall"

# Function to get weather data from the API
def get_weather_data(location):
    try:
        # Using geopy for GPS location
        geolocator = Nominatim(user_agent="weather_app")
        location_data = geolocator.geocode(location)
        if location_data:
            lat = location_data.latitude
            lon = location_data.longitude
        else:
            raise ValueError("Invalid location name")

        # Fetch current weather data
        response = requests.get(f"{BASE_URL}?lat={lat}&lon={lon}&appid={API_KEY}&units=metric")
        weather_data = response.json()

        # Fetch forecast data
        forecast_response = requests.get(f"{FORECAST_URL}?lat={lat}&lon={lon}&appid={API_KEY}&units=metric")
        forecast_data = forecast_response.json()

        return weather_data, forecast_data
    except Exception as e:
        messagebox.showerror("Error", str(e))
        return None, None

# Convert temperature units
def convert_temperature(temp, unit):
    if unit == "Celsius":
        return temp
    elif unit == "Fahrenheit":
        return (temp * 9/5) + 32
    return temp

# Display weather data on the GUI
def display_weather_data(weather_data, forecast_data, unit="Celsius"):
    try:
        city = weather_data["name"]
        temp = weather_data["main"]["temp"]
        description = weather_data["weather"][0]["description"]
        humidity = weather_data["main"]["humidity"]
        wind_speed = weather_data["wind"]["speed"]

        # Convert temperature if necessary
        temp = convert_temperature(temp, unit)

        # Update the GUI labels
        city_label.config(text=f"City: {city}")
        temp_label.config(text=f"Temperature: {temp:.2f}° {unit}")
        desc_label.config(text=f"Condition: {description.capitalize()}")
        humidity_label.config(text=f"Humidity: {humidity}%")
        wind_label.config(text=f"Wind Speed: {wind_speed} m/s")

        # Update forecast data (e.g., hourly)
        hourly_data = forecast_data.get("hourly", [])
        if hourly_data:
            forecast_text = "Hourly Forecast:\n"
            for hour in hourly_data[:5]:  # Only showing the first 5 hours
                hour_time = hour.get("dt")
                if hour_time:
                    hour_time = datetime.datetime.fromtimestamp(hour_time).strftime("%H:%M")
                hour_temp = hour.get("temp")
                hour_desc = hour.get("weather", [{}])[0].get("description", "No data")
                
                # Convert temperature if necessary
                if hour_temp is not None:
                    hour_temp = convert_temperature(hour_temp, unit)
                    forecast_text += f"{hour_time}: {hour_temp:.2f}° {unit}, {hour_desc}\n"
            
            forecast_label.config(text=forecast_text)
        else:
            forecast_label.config(text="No hourly forecast available.")

    except Exception as e:
        messagebox.showerror("Error", str(e))

# Function to update weather data based on user input
def update_weather():
    location = location_entry.get()
    unit = unit_combobox.get()
    weather_data, forecast_data = get_weather_data(location)
    if weather_data and forecast_data:
        display_weather_data(weather_data, forecast_data, unit)

# GUI setup
root = tk.Tk()
root.title("Weather App")

# City input
location_label = tk.Label(root, text="Enter City or ZIP Code:")
location_label.pack(pady=10)

location_entry = tk.Entry(root, width=25)
location_entry.pack(pady=10)

# Unit selection
unit_label = tk.Label(root, text="Select Temperature Unit:")
unit_label.pack(pady=10)

unit_combobox = ttk.Combobox(root, values=["Celsius", "Fahrenheit"], state="readonly")
unit_combobox.set("Celsius")
unit_combobox.pack(pady=10)

# Weather display labels
city_label = tk.Label(root, text="City:")
city_label.pack(pady=10)

temp_label = tk.Label(root, text="Temperature:")
temp_label.pack(pady=10)

desc_label = tk.Label(root, text="Condition:")
desc_label.pack(pady=10)

humidity_label = tk.Label(root, text="Humidity:")
humidity_label.pack(pady=10)

wind_label = tk.Label(root, text="Wind Speed:")
wind_label.pack(pady=10)

forecast_label = tk.Label(root, text="Hourly Forecast:")
forecast_label.pack(pady=10)

# Search button
search_button = tk.Button(root, text="Get Weather", command=update_weather)
search_button.pack(pady=20)

# Run the application
root.mainloop()
