import sgMail from '@sendgrid/mail';
import dotenv from 'dotenv';

dotenv.config();

sgMail.setApiKey(process.env.SG_KEY);

const sendSGMail = async ({ to, sender, subject, html, attachments, text }) => {
  try {
    const from = 'gelidcoding@gmail.com';

    const msg = {
      to: to,
      from: from,
      subject: subject,
      html: html,
      attachments,
    };
    console.log('success mailed');
    return sgMail.send(msg);
  } catch (error) {
    console.log(error);
  }
};

const sendMail = async (args) => {
  if (process.env.NODE_ENV === 'development') {
    return Promise.resolve();
  } else {
    return sendSGMail(args);
  }
};

export default { sendMail };
