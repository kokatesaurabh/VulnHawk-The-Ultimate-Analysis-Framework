# 6F93A0QXA5Ftgca2aMglOTJesAhaUBDS
# Using the AI21 Python SDK
import os
from ai21 import AI21Client
from ai21.models.chat import ChatMessage
os.environ["AI21_API_KEY"] = "6F93A0QXA5Ftgca2aMglOTJesAhaUBDS"

client = AI21Client()

def suggest_multiple_product_title():
    response = client.chat.completions.create(
        model="jamba-instruct",
        messages=[ChatMessage(
            role="user",
            content="Write a product title for a sports T-shirt to be published on an online retail platform. Include the following keywords: activewear, gym, dryfit."
    )],
        temperature=0.8,
        n=5 # Number of suggestions. Default = 1
    )
    for suggestion in response.choices:
        print(suggestion.message.content)

### RESPONSE
suggest_multiple_product_title()
"Premium Activewear Gym Dryfit T-Shirt for Ultimate Performance"
"ActiveGear DryFit Gym Performance T-Shirt for Men and Women"
"Ultra-DryFit Gym Activewear T-Shirt for High-Performance Workouts"
"Activewear Gym Dryfit Performance T-Shirt for Men and Women - Perfect for Workouts and Training"
"ActiveDry: Premium Dryfit Gym T-Shirt for Men - Best Activewear for Workouts"