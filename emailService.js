const nodemailer = require('nodemailer');
require('dotenv').config();

// Email configuration
const transporter = nodemailer.createTransport({
  service: 'gmail', // You can change this to your email provider
  auth: {
    user: process.env.EMAIL_USER || 'your-email@gmail.com',
    pass: process.env.EMAIL_PASS || 'your-app-password'
  }
});

// Email templates
const emailTemplates = {
  verification: (username, token) => ({
    subject: '🔐 Verify Your Email - abFORCE Authentication',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
          <h1 style="margin: 0; font-size: 28px;">🔐 abFORCE Authentication</h1>
          <p style="margin: 10px 0 0 0; opacity: 0.9;">Welcome to our secure platform!</p>
        </div>
        
        <div style="background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px;">
          <h2 style="color: #333; margin-top: 0;">Hello ${username}! 👋</h2>
          
          <p style="color: #666; line-height: 1.6;">
            Thank you for registering with abFORCE! To complete your account setup, 
            please verify your email address by clicking the button below:
          </p>
          
          <div style="text-align: center; margin: 30px 0;">
            <a href="${process.env.FRONTEND_URL || 'https://glittery-halva-254a81.netlify.app'}/verify-email?token=${token}" 
               style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                      color: white; 
                      padding: 15px 30px; 
                      text-decoration: none; 
                      border-radius: 25px; 
                      font-weight: bold; 
                      display: inline-block;">
              ✅ Verify Email Address
            </a>
          </div>
          
          <p style="color: #666; line-height: 1.6; font-size: 14px;">
            Or copy and paste this link into your browser:<br>
            <code style="background: #e9ecef; padding: 5px 10px; border-radius: 5px; word-break: break-all;">
              ${process.env.FRONTEND_URL || 'https://glittery-halva-254a81.netlify.app'}/verify-email?token=${token}
            </code>
          </p>
          
          <div style="background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 20px 0;">
            <p style="margin: 0; color: #856404; font-size: 14px;">
              <strong>⚠️ Important:</strong> This verification link will expire in 24 hours. 
              If you didn't create an account, please ignore this email.
            </p>
          </div>
          
          <hr style="border: none; border-top: 1px solid #dee2e6; margin: 30px 0;">
          
          <p style="color: #999; font-size: 12px; text-align: center; margin: 0;">
            This email was sent by abFORCE Authentication System<br>
            If you have any questions, please contact our support team.
          </p>
        </div>
      </div>
    `
  }),

  passwordReset: (username, token) => ({
    subject: '🔑 Reset Your Password - abFORCE Authentication',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
          <h1 style="margin: 0; font-size: 28px;">🔑 Password Reset</h1>
          <p style="margin: 10px 0 0 0; opacity: 0.9;">Secure password recovery</p>
        </div>
        
        <div style="background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px;">
          <h2 style="color: #333; margin-top: 0;">Hello ${username}! 👋</h2>
          
          <p style="color: #666; line-height: 1.6;">
            We received a request to reset your password for your abFORCE account. 
            Click the button below to create a new password:
          </p>
          
          <div style="text-align: center; margin: 30px 0;">
            <a href="${process.env.FRONTEND_URL || 'https://glittery-halva-254a81.netlify.app'}/password-reset?token=${token}" 
               style="background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%); 
                      color: white; 
                      padding: 15px 30px; 
                      text-decoration: none; 
                      border-radius: 25px; 
                      font-weight: bold; 
                      display: inline-block;">
              🔑 Reset Password
            </a>
          </div>
          
          <p style="color: #666; line-height: 1.6; font-size: 14px;">
            Or copy and paste this link into your browser:<br>
            <code style="background: #e9ecef; padding: 5px 10px; border-radius: 5px; word-break: break-all;">
              ${process.env.FRONTEND_URL || 'https://glittery-halva-254a81.netlify.app'}/password-reset?token=${token}
            </code>
          </p>
          
          <div style="background: #f8f9fa; border: 2px solid #dee2e6; padding: 20px; border-radius: 8px; margin: 20px 0;">
            <h3 style="color: #495057; margin: 0 0 10px 0; font-size: 16px;">📋 Reset Token (Copy & Paste)</h3>
            <p style="color: #666; font-size: 14px; margin: 0 0 10px 0;">
              If the button above doesn't work, you can manually enter this token:
            </p>
            <div style="background: #ffffff; border: 1px solid #ced4da; padding: 15px; border-radius: 5px; text-align: center;">
              <code style="font-family: 'Courier New', monospace; font-size: 18px; font-weight: bold; color: #dc3545; letter-spacing: 1px; word-break: break-all;">
                ${token}
              </code>
            </div>
            <p style="color: #6c757d; font-size: 12px; margin: 10px 0 0 0;">
              ⚠️ This token is case-sensitive and expires in 1 hour
            </p>
          </div>
          
          <div style="background: #f8d7da; border: 1px solid #f5c6cb; padding: 15px; border-radius: 5px; margin: 20px 0;">
            <p style="margin: 0; color: #721c24; font-size: 14px;">
              <strong>⚠️ Security Notice:</strong> This reset link will expire in 1 hour. 
              If you didn't request this reset, please ignore this email and your password will remain unchanged.
            </p>
          </div>
          
          <hr style="border: none; border-top: 1px solid #dee2e6; margin: 30px 0;">
          
          <p style="color: #999; font-size: 12px; text-align: center; margin: 0;">
            This email was sent by abFORCE Authentication System<br>
            For security reasons, never share this link with anyone.
          </p>
        </div>
      </div>
    `
  })
};

// Send email function
const sendEmail = async (to, template, data) => {
  try {
    const emailContent = emailTemplates[template](data.username, data.token);
    
    const mailOptions = {
      from: `"abFORCE Authentication" <${process.env.EMAIL_USER || 'noreply@abforce.com'}>`,
      to: to,
      subject: emailContent.subject,
      html: emailContent.html
    };

    const result = await transporter.sendMail(mailOptions);
    console.log('✅ Email sent successfully:', result.messageId);
    return { success: true, messageId: result.messageId };
  } catch (error) {
    console.error('❌ Email sending failed:', error.message);
    return { success: false, error: error.message };
  }
};

module.exports = { sendEmail };
