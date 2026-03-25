import nodemailer from "nodemailer";

if (
  !process.env.SMTP_HOST ||
  !process.env.SMTP_USER ||
  !process.env.SMTP_PASS
) {
  throw new Error("Missing SMTP environment variables");
}

const host = process.env.SMTP_HOST;
const port = Number(process.env.SMTP_PORT);
const user = process.env.SMTP_USER;
const pass = process.env.SMTP_PASS;
const from = process.env.EMAIL_FROM;

const transporter = nodemailer.createTransport({
  host,
  port,
  secure: false,
  auth: {
    user,
    pass,
  },
});

export async function sendEmail(to: string, subject: string, html: string) {
  await transporter.sendMail({
    from,
    to,
    subject,
    html,
  });
}
