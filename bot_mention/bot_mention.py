from telegram import Update
from telegram.ext import Application, MessageHandler, filters, ContextTypes
from telegram.helpers import mention_html

# Initialize the bot with your token
TOKEN = "6743612662:AAFiKelfeEFxNTGQRORImQmbYocCPeisuC0"
app = Application.builder().token(TOKEN).build()

# List of prohibited words
PROHIBITED_WORDS = ["fuck", "site"]

# Function to handle messages and check for prohibited words
async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = update.message

    # Check if the message has text
    if message.text:
        # Check for prohibited words
        if any(word.lower() in message.text.lower() for word in PROHIBITED_WORDS):
            await message.delete()  # Delete the message
            
            # Mention the user who sent the prohibited message
            mention = mention_html(message.from_user.id, message.from_user.first_name)
            await context.bot.send_message(
                chat_id=message.chat_id,
                text=f"សូមមេត្តាមិនប្រើពាក្យមិនសមរម្យ {mention}! ខ្ញុំនឹងបិតសាររបស់អ្នក!!",
                parse_mode="HTML"
            )
            return

    # Check if the message contains "@allknea" to mention all members
    if "@allknea" in (message.text.lower() if message.text else ""):
        # Fetch all chat members and construct the mention message
        members = await context.bot.get_chat_administrators(message.chat_id)
        mentions = " ".join(mention_html(user.user.id, user.user.first_name) for user in members)
        
        # Send a message mentioning all members
        await context.bot.send_message(
            chat_id=message.chat_id,
            text=f"Attention: {mentions}",
            parse_mode="HTML"
        )

# Add the message handler
app.add_handler(MessageHandler(filters.TEXT | filters.PHOTO | filters.Document.ALL, handle_message))

# Start the bot
app.run_polling()
