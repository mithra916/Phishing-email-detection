function analyzeEmail() {
    const emailText = document.getElementById("emailText").value;
    const resultDiv = document.getElementById("result");

    if (emailText.trim() === "") {
        resultDiv.innerHTML = "⚠️ Please enter email content";
        resultDiv.style.color = "red";
        return;
    }

    fetch("/predict", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({ email_text: emailText })
    })
    .then(response => response.json())
    .then(data => {
        resultDiv.innerHTML = `
            <b>Prediction:</b> ${data.prediction}<br>
            <b>Confidence:</b> ${(data.confidence * 100).toFixed(2)}%<br>
            <b>Emotion Risk Score:</b> ${(data.emotion_score * 100).toFixed(1)}%<br>
            <b>Risk Level:</b> ${data.risk_level}<br>
            <b>URLs Found:</b> ${data.url_count}
        `;

        if (data.risk_level === "High") {
            resultDiv.style.color = "red";
        } else if (data.risk_level === "Medium") {
            resultDiv.style.color = "orange";
        } else {
            resultDiv.style.color = "green";
        }
    })
    .catch(error => {
        resultDiv.innerHTML = "❌ Error analyzing email";
        resultDiv.style.color = "red";
    });
}
