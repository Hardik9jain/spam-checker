async function checkSpam() {
  const message = document.getElementById("messageInput").value;

  const res = await fetch('/check-spam', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message })
  });

  const data = await res.json();
  const resultDiv = document.getElementById("result");
  resultDiv.textContent = data.message;
  resultDiv.style.color = data.is_spam ? "red" : "green";

  // 🔔 Show alert if spam detected
  if (data.is_spam) {
    alert("⚠️ This message has been flagged as spam!");
  }
}


async function checkSpamCategories() {
  const message = document.getElementById("messageInput").value;

  const res = await fetch('/check-categories', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message })
  });

  const data = await res.json();
  const categoryResultDiv = document.getElementById("categoryResult");
  categoryResultDiv.innerHTML = data.message;
}
function clearText() {
  document.getElementById("messageInput").value = "";
  document.getElementById("result").textContent = "";
  document.getElementById("categoryResult").textContent = "";
}

function showHelp() {
  alert("Enter a message and click one of the buttons:\n\n" +
        "• Check for Spam: Detects general spam keywords.\n" +
        "• Check Spam Categories: Shows the type of spam if detected.\n" +
        "• Clear Text: Clears the message input.\n" +
        "• Exit: Closes this tab.");
}

function exitApp() {
  if (confirm("Are you sure you want to exit?")) {
    window.close();
  }
}


async function showCategoryOnly() {
  const message = document.getElementById("messageInput").value;

  const res = await fetch('/classify-category', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message })
  });

  const data = await res.json();
  const categoryResultDiv = document.getElementById("categoryResult");

  categoryResultDiv.innerHTML = `<strong>Category:</strong> ${data.category}`;
}

