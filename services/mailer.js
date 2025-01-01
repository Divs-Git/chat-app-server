import sgMail from '@sendgrid/mail';
import dotenv from 'dotenv';

dotenv.config({ path: '../config.env' });

sgMail.setApiKey(process.env.SG_KEY);

const sendSGMail = async ({
  recipient,
  sender,
  subject,
  html,
  text,
  attachments,
}) => {
  try {
    const from = sender || process.env.SENDGRID_SENDER;

    const msg = {
      to: recipient,
      from,
      subject,
      html,
      text,
      attachments,
    };

    return sgMail.send(msg);
  } catch (error) {
    console.log(error);
  }
};

export default async function sendMail({ args }) {
  // If the environment is development, return a resolved promise to prevent sending emails
  if (process.env.NODE_ENV === 'development') {
    return new Promise.resolve();
  } else {
    return sendSGMail(args);
  }
}
