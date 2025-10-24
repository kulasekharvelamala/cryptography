import resend

resend.api_key = "re_fARYEwTq_83o3NZrvGemy6XkEKy4Wkx35"

r = resend.Emails.send({
  "from": "onboarding@resend.dev",
  "to": "kulasekharvelamala@gmail.com",
  "subject": "Hello World",
  "html": "<p>Congrats on sending your <strong>first email</strong>!</p>"
})
