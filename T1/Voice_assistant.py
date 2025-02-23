import speech_recognition as sr
import pyttsx3
import datetime
import webbrowser
import time

# Initialize text-to-speech engine
engine = pyttsx3.init()

def speak(text):
    """Convert text to speech with error handling"""
    try:
        engine.say(text)
        engine.runAndWait()
    except Exception as e:
        print(f"Speech error: {str(e)}")

def get_microphone():
    """Safely initialize and return microphone"""
    try:
        mic = sr.Microphone()
        # Quick test to verify microphone works
        with mic as source:
            sr.Recognizer().adjust_for_ambient_noise(source, duration=0.5)
        return mic
    except Exception as e:
        print(f"Microphone initialization failed: {str(e)}")
        return None

def take_command():
    """Robust voice command recognition"""
    r = sr.Recognizer()
    mic = get_microphone()
    
    if not mic:
        speak("Microphone not available")
        return ""
    
    try:
        with mic as source:
            print("Calibrating...")
            r.adjust_for_ambient_noise(source, duration=1)
            print("Listening...")
            audio = r.listen(source, timeout=3, phrase_time_limit=5)
            
        return r.recognize_google(audio).lower()
    
    except sr.WaitTimeoutError:
        print("No speech detected")
        return ""
    except sr.UnknownValueError:
        print("Could not understand audio")
        return ""
    except sr.RequestError as e:
        print(f"API error: {str(e)}")
        return ""
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        return ""

def main():
    speak("Hello! I'm your voice assistant. How can I help you?")
    
    while True:
        try:
            query = take_command()
            if not query:
                continue
                
            print(f"Processing command: {query}")
            
            if 'hello' in query:
                speak("Hello! How can I assist you today?")
                
            elif 'time' in query:
                current_time = datetime.datetime.now().strftime("%I:%M %p")
                speak(f"The current time is {current_time}")
                
            elif 'date' in query:
                current_date = datetime.datetime.now().strftime("%B %d, %Y")
                speak(f"Today's date is {current_date}")
                
            elif 'search' in query:
                speak("What would you like me to search for?")
                search_term = take_command()
                if search_term:
                    url = f"https://google.com/search?q={search_term.replace(' ', '+')}"
                    webbrowser.open(url)
                    speak(f"Showing results for {search_term}")
                else:
                    speak("No search term detected")
                    
            elif 'exit' in query or 'quit' in query:
                speak("Goodbye! Have a great day!")
                break
                
            else:
                speak("I didn't understand that command. Please try again.")
                
        except KeyboardInterrupt:
            speak("Goodbye!")
            break
        except Exception as e:
            print(f"Main loop error: {str(e)}")
            time.sleep(1)

if __name__ == "__main__":
    # Verify dependencies first
    try:
        import speech_recognition
        import pyaudio
        main()
    except ImportError:
        print("Missing dependencies. Install required packages:")
        print("pip install speechrecognition pyaudio pyttsx3")