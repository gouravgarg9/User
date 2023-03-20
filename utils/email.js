const nodemailer = require("nodemailer");
const pug = require("pug");
const { convert: htmlToText } = require("html-to-text");
const path = require("path");
module.exports = class Email {
  constructor(user) {
    this.to = user.email;
    this.firstName = user.username.split(" ")[0];
    this.from = `Gourav Garg <${process.env.MAIL_FROM}>`;
  }

  newTransport() {
    if (process.env.NODE_ENV === "production") {
      return nodemailer.createTransport({
        host: "smtp-relay.sendinblue.com",
        port: 587,
        auth: {
          user: process.env.SENDINBLUE_USERNAME,
          pass: process.env.SENDINBLUE_PASSWORD,
        },
      });
    } else {
      return nodemailer.createTransport({
        host: process.env.MAILHOST_DEV,
        port: process.env.MAILPORT_DEV,
        auth: {
          user: process.env.MAILUSERNAME_DEV,
          pass: process.env.MAILPASSWORD_DEV,
        },
      });
    }
  }

  async sendEmail(template, subject, vars) {
    const html = pug.renderFile(
      path.join(__dirname, `../views/emails/${template}.pug`),
      vars
    );
    const mailOptions = {
      from: this.from,
      to: this.to,
      subject,
      html,
      text: htmlToText(html),
    };
    await this.newTransport().sendMail(mailOptions);
  }

  async sendWelcome(vars) {
    await this.sendEmail("welcome", " Welcome to the Family! ", {
      firstName: this.firstName,
      ...vars,
    });
  }

  async sendResetPasswordURL(vars) {
    await this.sendEmail(
      "resetPassword",
      " Password Reset Link (Valid for 10 minutes)!",
      { firstName: this.firstName, ...vars }
    );
  }

  async sendSignUpOTP(vars) {
    await this.sendEmail("signupOTP", " Welcome to the Family! ", {
      firstName: this.firstName,
      ...vars,
    });
  }
  async sendVerified(vars) {
    await this.sendEmail("verified", " Welcome to the Family! ", {
      firstName: this.firstName,
      ...vars,
    });
  }
  async sendPasswordChanged(vars) {
    await this.sendEmail("passwordChanged", " Welcome to the Family! ", {
      firstName: this.firstName,
      ...vars,
    });
  }
  async sendInformationUpdated(vars) {
    await this.sendEmail("userUpdated", " Welcome to the Family! ", {
      firstName: this.firstName,
      ...vars,
    });
  }
};
