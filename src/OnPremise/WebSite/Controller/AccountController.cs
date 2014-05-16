/*
 * Copyright (c) Dominick Baier, Brock Allen.  All rights reserved.
 * see license.txt
 */

using System;
using System.IdentityModel.Tokens;
using System.Net.Mail;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;
using System.Web.UI;
using Thinktecture.IdentityServer.Protocols;
using Thinktecture.IdentityServer.Repositories;
using Thinktecture.IdentityServer.Web.ViewModels;
using System.Security.Cryptography;
using System.Web.Profile;
using System.Collections;
using System.Linq;
using System.Configuration;
using System.Data;
using System.Data.SqlServerCe;
using System.Web.Script;
using System.Collections.Generic;
using System.Data.SqlClient;

namespace Thinktecture.IdentityServer.Web.Controllers
{
    public class AccountController : AccountControllerBase
    {
      
        public AccountController()
            : base()
        { }

        public AccountController(IUserRepository userRepository, IConfigurationRepository configurationRepository)
            : base(userRepository, configurationRepository)
        { }

        // shows the signin screen
        public ActionResult SignIn(string returnUrl, bool mobile = false)
        {
            // you can call AuthenticationHelper.GetRelyingPartyDetailsFromReturnUrl to get more information about the requested relying party

            var vm = new SignInModel()
            {
                ReturnUrl = returnUrl,
                ShowClientCertificateLink = ConfigurationRepository.Global.EnableClientCertificateAuthentication
            };

            if (mobile) vm.IsSigninRequest = true;
            return View("OSCSignIn", vm);
        }
       
        // handles the signin
        [HttpPost]
        [ValidateAntiForgeryToken]
        [OutputCache(Location = OutputCacheLocation.None, NoStore = true)]
        public ActionResult SignIn(SignInModel model)
        {
            if (ModelState.IsValid)
            {
                if (UserRepository.ValidateUser(model.UserName, model.Password))
                {
                    // establishes a principal, set the session cookie and redirects
                    // you can also pass additional claims to signin, which will be embedded in the session token
                   // string role = GetRoleByUserName(model.UserName);
                    return SignIn(
                        model.UserName,
                        AuthenticationMethods.Password,
                        model.ReturnUrl,
                        model.EnableSSO,
                        ConfigurationRepository.Global.SsoCookieLifetime);
                }
            }

            ModelState.AddModelError("", Resources.AccountController.IncorrectCredentialsNoAuthorization);

            model.ShowClientCertificateLink = ConfigurationRepository.Global.EnableClientCertificateAuthentication;
            return View("OSCSignIn", model);
        }

        // handles client certificate based signin
        public ActionResult CertificateSignIn(string returnUrl)
        {
            if (!ConfigurationRepository.Global.EnableClientCertificateAuthentication)
            {
                return new HttpNotFoundResult();
            }

            var clientCert = HttpContext.Request.ClientCertificate;

            if (clientCert != null && clientCert.IsPresent && clientCert.IsValid)
            {
                string userName;
                if (UserRepository.ValidateUser(new X509Certificate2(clientCert.Certificate), out userName))
                {
                    // establishes a principal, set the session cookie and redirects
                    // you can also pass additional claims to signin, which will be embedded in the session token

                    return SignIn(
                        userName,
                        AuthenticationMethods.X509,
                        returnUrl,
                        false,
                        ConfigurationRepository.Global.SsoCookieLifetime);
                }
            }

            return View("Error");
        }

        // shows the Forgot Password screen
        public ActionResult ForgotPassword(string returnUrl, bool mobile = false)
        {

            var vm = new ForgotPassword()
            {
                ReturnUrl = returnUrl
            };
            return View("ForgotPassword", vm);
        }

        // shows the Reset Password screen
        public ActionResult ResetPassword(string returnUrl, bool mobile = false)
        {

            var vm = new ResetPassword()
            {
                ReturnUrl = returnUrl
            };
            return View("ResetPassword", vm);
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        [OutputCache(Location = OutputCacheLocation.None, NoStore = true)]
        public ActionResult ResetPassword(ResetPassword model)
        {
            if (ModelState.IsValid)
            {

            }
            return View("ResetPassword", model);
        }

        #region Mailing Service
        [HttpPost]
        public JsonResult NotificationEmail(string uName)
        {
            string EmailStatus = String.Empty;

            MembershipUser mu = Membership.GetUser(uName);
            string userDefaultEmail = mu.Email;
            string email = userDefaultEmail;
            MailMessage mail = new MailMessage();
            mail.From = new MailAddress("noreplytimesheetcgs@gmail.com", "OSCID");
            mail.To.Add(email);
            mail.Subject = "Permissions Updated - This mail was sent by OSCid ";
            mail.IsBodyHtml = true;
           
            string body = "<html><head><body><table>" +
                "<tr><td>Dear " + uName + ",</td></tr>" +
                "<tr><td></td></tr>" +
                "<tr><td> Your Permissions has been Changed</td></tr>" +
                "<tr><td></td></tr>" +              
                "<tr><td></td></tr>" +
                "</table></body></head></html>";
            mail.Body = body;
            SmtpClient SmtpServer = new SmtpClient("smtp.gmail.com", 587);
            SmtpServer.EnableSsl = true;
            SmtpServer.UseDefaultCredentials = false;
            SmtpServer.Credentials = new System.Net.NetworkCredential("noreplytimesheetcgs@gmail.com", "Passw0rd_1");
            SmtpServer.Send(mail);
            EmailStatus = "Email sent to the User's default MailId.";

            return Json(EmailStatus, JsonRequestBehavior.AllowGet);
        }
        [HttpPost]
        public JsonResult SendEmail(string uName, string email)
        {
            string EmailStatus = String.Empty;

            if (ModelState.IsValid)
            {
                MembershipUser mu = Membership.GetUser(uName);
                string userDefaultEmail = mu.Email;
                string userID = mu.ProviderUserKey.ToString();
                string UIDKey = EncryptData(userID);
                UIDKey = UIDKey.Replace(" ", "+");
                if (userDefaultEmail == email)
                {
                    MailMessage mail = new MailMessage();
                    mail.From = new MailAddress("noreplytimesheetcgs@gmail.com", "OSCID");
                    mail.To.Add(email);
                    mail.Subject = "Reset Password - This mail was sent by OSCid ";
                    mail.IsBodyHtml = true;
                    string baseUrl = string.Format("{0}://{1}{2}", Request.Url.Scheme, Request.Url.Authority, Url.Content("~"));
                    string body = "<html><head><body><table>" +
                        "<tr><td>Dear " + uName + ",</td></tr>" +
                        "<tr><td></td></tr>" +
                        "<tr><td>To Reset your password. Please Click on to the following Link</td></tr>" +
                        "<tr><td></td></tr>" +
                        "<tr><td>" + baseUrl + "Account/ResetPassword?Key=" + UIDKey + "</td></tr>" +
                        "<tr><td></td></tr>" +
                        "</table></body></head></html>";
                    mail.Body = body;
                    SmtpClient SmtpServer = new SmtpClient("smtp.gmail.com", 587);
                    SmtpServer.EnableSsl = true;
                    SmtpServer.UseDefaultCredentials = false;
                    SmtpServer.Credentials = new System.Net.NetworkCredential("noreplytimesheetcgs@gmail.com", "Passw0rd_1");
                    SmtpServer.Send(mail);
                    EmailStatus = "Email Sent Succesfully.Please Login to your Email to Reset Password";
                }
                else
                {
                    EmailStatus = "Username and email does not match.";
                }

            }
            else
            {
                ModelState.AddModelError("", Resources.AccountController.IncorrectCredentialsNoAuthorization);
            }
            return Json(EmailStatus, JsonRequestBehavior.AllowGet);

        }
        #endregion

        // handles Back button in forgot Password screen
        [HttpPost]
        [ValidateAntiForgeryToken]
        [OutputCache(Location = OutputCacheLocation.None, NoStore = true)]
        public ActionResult Back(ForgotPassword model)
        {
            if (ModelState.IsValid)
            {

            }

            ModelState.AddModelError("", Resources.AccountController.IncorrectCredentialsNoAuthorization);

            return View("ForgotPassword", model);
        }
        [HttpPost]
        public ActionResult Registration(Registration model)
        {
            SignInModel modelSign = new SignInModel()
            {
                ReturnUrl = model.ReturnUrl,
            };
            return View("OSCSignIn", modelSign);
        }
        // shows the Registration screen
        public ActionResult Registration(string returnUrl, bool mobile = false)
        {

            var vm = new Registration()
            {
                ReturnUrl = returnUrl,
            };

            return View("Registration", vm);
        }
        // User Approval page after click
        public ActionResult ApproveUser(string UserName, bool Status)
        {
            ViewData["Result"] = string.Empty;
            MembershipUser adminuser = Membership.GetUser();
            MyCustomProfile adminprofile = MyCustomProfile.GetProfile(adminuser.UserName);            
            MembershipUser user = Membership.GetUser(UserName);           
            if (Status)
            {
                user.IsApproved = Status;
                MyCustomProfile userprofile = MyCustomProfile.GetProfile(user.UserName);
                userprofile.Application=adminprofile.Application;
                userprofile.Save();
                Membership.UpdateUser(user);
                ViewData["Result"] = user.UserName + " Approved Successfully!";
            }
            else
            {
                Membership.DeleteUser(user.UserName, true);
                ViewData["Result"] = user.UserName + " Rejected!";
            }

            return View("UserApproval", GetunapprovedUsers());
        }


        // shows the User Approval screen
        public ActionResult UserApproval()
        {
            if (HttpContext.User.Identity.IsAuthenticated)
            {

                return View("UserApproval", GetunapprovedUsers());
            }
            else
            {
                var vm = new SignInModel()
                {
                    ReturnUrl = "",
                    ShowClientCertificateLink = ConfigurationRepository.Global.EnableClientCertificateAuthentication
                };

                //if (mobile) vm.IsSigninRequest = true;
                return RedirectToAction("SignIn");
            }
        }

        public ActionResult EditUserRoles(string UseName)
        {
            return View();
        }

        // handles Update button in forgot Password screen

        [HttpPost]
        public JsonResult UpdatePassword(string newPwd, string userId)
        {
            string Result = String.Empty;
            string UID = DecryptString(userId.Trim());
            if (ModelState.IsValid)
            {
                System.Guid UserID = new Guid(UID);
                MembershipUser mu = Membership.GetUser(UserID);
                mu.ChangePassword(mu.ResetPassword(), newPwd);
                Result = "Password updated Successfully.";
            }

            ModelState.AddModelError("", Resources.AccountController.IncorrectCredentialsNoAuthorization);

            return Json(Result, JsonRequestBehavior.AllowGet);
        }
        /// <summary>
        /// Registration Method
        /// </summary>
        /// <param name="userName"></param>
        /// <param name="password"></param>
        /// <param name="company"></param>
        /// <param name="emailId"></param>
        /// <param name="firstName"></param>
        /// <param name="lastName"></param>
        /// <param name="contactMail"></param>
        /// <param name="app"></param>
        /// <returns></returns>
        [HttpPost]
        public JsonResult Register(string userName, string password, string company, string emailId, string firstName, string lastName, string contactMail,string app)
        {
            String Result = String.Empty;
            try
            {
                MembershipUser checkUser = Membership.GetUser(userName);

                if (checkUser == null)
                {
                    MembershipCreateStatus status;
                    MembershipUser mu = Membership.CreateUser(userName, password, emailId, "What is your User Name", userName, false, out status);

                    MyCustomProfile profile = MyCustomProfile.GetProfile(userName);
                    profile.FirstName = firstName;
                    profile.LastName = lastName;
                    profile.Company = company;
                    profile.ContactEmail = contactMail;
                    profile.Application = app;
                    profile.Status = "0";
                    profile.Save();
                    Result = "User Registered Successfully.";
                }
                else
                {
                    Result = "UserName already Exists.";
                }

            }
            catch (Exception ex)
            {
                Result = "Failed to Register the Current User.";

            }
            return Json(Result, JsonRequestBehavior.AllowGet);
        }
        
        [HttpPost]
        public ActionResult AssignUserRoles(AssignUserRolesModel model)
        {
            DeleteRolesbyUser();
            SaveRolestoUser(model);
            
            model = GetapprovedUsers(model);
            model.BindList = new List<BindViewModel>();

            model.Time = DateTime.Now.ToString();
            model.UserRole = getCurrentUserRole();

            for (int tcount = 0; tcount < model.Users.Count; tcount++)
            {
                model.BindList.Add(new BindViewModel());
                model.BindList[tcount].TextField = model.Users[tcount].UserName;
                model.BindList[tcount].ValueField = model.Users[tcount].UserId;
            }
            ViewData["Result"] = "Updated Roles Successfully";        
            return View(model);
        }
      
        [HttpPost]
        public JsonResult UpdateUserRoles(string roles)
        {
            string Result = String.Empty;
            if (roles != "")
            {
                List<string> selectedRoles = new List<string>(roles.Split(','));
                if (selectedRoles.Count > 0)
                {
                    DeleteRolesbyUser();
                    SaveRoles(selectedRoles);
                    Result = "Updated Roles Successfully";
                }
               
            }
            else
            {
                DeleteRolesbyUser();
                Result = "Updated Roles Successfully";
            }         
            return Json(Result, JsonRequestBehavior.AllowGet);
        }
        [HttpPost]
        public ActionResult CurrentUserRoles(AssignUserRolesModel model)
        {
            ViewData["Result"] = string.Empty;
            string result = string.Empty;
            model.Application = Session["Application"].ToString();
            model.RolesinUserTable = new List<userRoles>();
            model.UserRolesTable = new List<userRoles>();
            model = GetapprovedUsers(model);

            foreach (AssignUserRolesModel.approveduser user in model.Users)
            {
                if (user.UserId == model.ValueField)
                {
                    Session["SelectedUserName"] = user.UserName;
                }
            }
            Session["SelectedUser"] = model.ValueField;
           
            MembershipUser currentadmin = Membership.GetUser();
            MyCustomProfile adminprofile = MyCustomProfile.GetProfile(currentadmin.UserName);

            DataTable userRoles = GetRolesByUser();  

            userRoles userSelectedRoles = new userRoles();
            userSelectedRoles.Roles = new List<userRoles.Role>();                     
            foreach (DataRow row in userRoles.Rows)
            {
                userRoles.Role selectedRole = new userRoles.Role();
                selectedRole.Rolename = row["RoleName"].ToString();
                selectedRole.RoleId = row["RoleId"].ToString();
                userSelectedRoles.Roles.Add(selectedRole);
            }
            
            DataTable RolesTable = GetRolesByApplication("/" + adminprofile.Application);           

            userRoles objuserRoles = new userRoles();           
            objuserRoles.Roles = new List<userRoles.Role>();
            foreach (DataRow rowRole in RolesTable.Rows)
            {
                userRoles.Role objRole = new userRoles.Role();
                objRole.Rolename = rowRole["RoleName"].ToString();
                objRole.RoleId = rowRole["RoleId"].ToString();              
                objuserRoles.Roles.Add(objRole);                
            }
            model.RolesinUserTable.Add(objuserRoles);
            model.UserRolesTable.Add(userSelectedRoles);

            int tcount;
            model.BindList = new List<BindViewModel>();
            model.Time = DateTime.Now.ToString();
            model.UserRole = getCurrentUserRole();
            for (tcount = 0; tcount < model.Users.Count; tcount++)
            {
                model.BindList.Add(new BindViewModel());
                model.BindList[tcount].TextField = model.Users[tcount].UserName;
                model.BindList[tcount].ValueField = model.Users[tcount].UserId;
            }

            return View("RoleAdmin_AssignUserRoles", model);
        }
        [HttpPost]
        public ActionResult AssignUserRolesPost(AssignUserRolesModel model)
        {
            ViewData["Result"] =string.Empty;
            string result = string.Empty;
            model = GetapprovedUsers(model);
            Session["SelectedUser"] = model.ValueField;

            using (SqlCeConnection c = new SqlCeConnection(ConfigurationManager.ConnectionStrings["ProviderDB"].ToString()))
            {
                
                using (SqlCeDataAdapter a = new SqlCeDataAdapter(
                    "SELECT distinct Applications.ApplicationName FROM Applications INNER JOIN Roles ON Applications.ApplicationId = Roles.ApplicationId INNER JOIN UsersInRoles ON Roles.RoleId = UsersInRoles.RoleId where UsersInRoles.UserId = '" + model.ValueField + "' ORDER BY Applications.ApplicationName  ", c))
                {
                    DataTable dtApplication = new DataTable();
                    a.Fill(dtApplication);

                    if (dtApplication != null && dtApplication.Rows.Count > 0)
                    {
                        model.RolesinUserTable = new List<userRoles>();
                        List<string> selected = new List<string>();
                        foreach (DataRow drow in dtApplication.Rows)
                        {
                            {
                                userRoles objuserRoles = new userRoles();
                                objuserRoles.Application = drow["ApplicationName"].ToString();

                                objuserRoles.Roles = new List<userRoles.Role>();

                                foreach (DataRow rowRole in GetRolesByUser().Rows)
                                {
                                    if (objuserRoles.Application == rowRole["ApplicationName"].ToString())
                                    {
                                        userRoles.Role objRole = new userRoles.Role();
                                        objRole.Rolename = rowRole["RoleName"].ToString();
                                        objRole.RoleId = rowRole["RoleId"].ToString();
                                        selected.Add(objRole.RoleId);
                                        objuserRoles.Roles.Add(objRole);
                                    }
                                }
                                model.RolesinUserTable.Add(objuserRoles);
                                model.SelectedRoles = selected;
                            }
                        }
                    }
                }
            }

            using (SqlCeConnection c = new SqlCeConnection(ConfigurationManager.ConnectionStrings["ProviderDB"].ToString()))
            {
                using (SqlCeDataAdapter a = new SqlCeDataAdapter(
                    "SELECT Applications.ApplicationName From Applications  ORDER BY Applications.ApplicationName", c))
                {
                    DataTable dtApplication = new DataTable();
                    a.Fill(dtApplication);

                    if (dtApplication != null && dtApplication.Rows.Count > 0)
                    {
                        model.UserRolesTable = new List<userRoles>();
                        foreach (DataRow drow in dtApplication.Rows)
                        {
                            userRoles objuserRoles = new userRoles();
                            objuserRoles.Application = drow["ApplicationName"].ToString();

                            objuserRoles.Roles = new List<userRoles.Role>();
                            foreach (DataRow rowRole in GetRolesByApplication(objuserRoles.Application).Rows)
                            {

                                userRoles.Role objRole = new userRoles.Role();
                                objRole.Rolename = rowRole["RoleName"].ToString();
                                objRole.RoleId = rowRole["RoleId"].ToString();

                                objuserRoles.Roles.Add(objRole);
                            }
                            model.UserRolesTable.Add(objuserRoles);
                        }
                    }
                }
            }

            int tcount;
            model.BindList = new List<BindViewModel>();
            model.Time = DateTime.Now.ToString();
            model.UserRole = getCurrentUserRole();
            for (tcount = 0; tcount < model.Users.Count; tcount++)
            {
                model.BindList.Add(new BindViewModel());

                model.BindList[tcount].TextField = model.Users[tcount].UserName;
                model.BindList[tcount].ValueField = model.Users[tcount].UserId;
            }
           
            return View("AssignUserRoles", model);
        }

       
        // shows the User Assign User Roles screen for Role Admin
        public ActionResult RoleAdmin_AssignUserRoles()
        {
             if (HttpContext.User.Identity.IsAuthenticated)
            {
                Session["SelectedUser"] = string.Empty;                          
                MembershipUser currentuser = Membership.GetUser();
                MyCustomProfile profile = MyCustomProfile.GetProfile(currentuser.UserName);
                Session["Application"] = profile.Application;
                AssignUserRolesModel aum = new AssignUserRolesModel();
                aum = GetapprovedUsers(aum);
                aum.Application = profile.Application;
                int tcount;
                aum.BindList = new List<BindViewModel>();                
                aum.Time = DateTime.Now.ToString();
                aum.UserRole = getCurrentUserRole();
                for (tcount = 0; tcount < aum.Users.Count; tcount++)
                {
                    aum.BindList.Add(new BindViewModel());
                    aum.BindList[tcount].TextField = aum.Users[tcount].UserName;
                    aum.BindList[tcount].ValueField = aum.Users[tcount].UserId;
                }
                return View(aum);
            }
             else
             {
                 var vm = new SignInModel()
                 {
                     ReturnUrl = "",
                     ShowClientCertificateLink = ConfigurationRepository.Global.EnableClientCertificateAuthentication
                 };

                 //if (mobile) vm.IsSigninRequest = true;
                 return RedirectToAction("SignIn");
             }


        }
        // shows the User Assign User Roles screen for System Admin
        public ActionResult AssignUserRoles()
        {
            if (HttpContext.User.Identity.IsAuthenticated)
            {
                Session["SelectedUser"] = string.Empty;
                AssignUserRolesModel aum = new AssignUserRolesModel();
                aum = GetapprovedUsers(aum);
                int tcount;
                aum.BindList = new List<BindViewModel>();
                MembershipUser currentuser = Membership.GetUser();
                MyCustomProfile profile = MyCustomProfile.GetProfile(currentuser.UserName);
                aum.Application = profile.Application;
                aum.Time = DateTime.Now.ToString();
                aum.UserRole = getCurrentUserRole();
                for (tcount = 0; tcount < aum.Users.Count; tcount++)
                {
                    aum.BindList.Add(new BindViewModel());
                    aum.BindList[tcount].TextField = aum.Users[tcount].UserName;
                    aum.BindList[tcount].ValueField = aum.Users[tcount].UserId;
                }
                return View(aum);
            }
            else
            {
                var vm = new SignInModel()
                {
                    ReturnUrl = "",
                    ShowClientCertificateLink = ConfigurationRepository.Global.EnableClientCertificateAuthentication
                };
                //if (mobile) vm.IsSigninRequest = true;
                return RedirectToAction("SignIn");
            }

        }
       
        #region Methods

        #region Encryption/Decryption
        const string passphrase = "OSCID";
        public static string EncryptData(string Message)
        {
            byte[] Results;
            System.Text.UTF8Encoding UTF8 = new System.Text.UTF8Encoding();
            MD5CryptoServiceProvider HashProvider = new MD5CryptoServiceProvider();
            byte[] TDESKey = HashProvider.ComputeHash(UTF8.GetBytes(passphrase));
            TripleDESCryptoServiceProvider TDESAlgorithm = new TripleDESCryptoServiceProvider();
            TDESAlgorithm.Key = TDESKey;
            TDESAlgorithm.Mode = CipherMode.ECB;
            TDESAlgorithm.Padding = PaddingMode.PKCS7;
            byte[] DataToEncrypt = UTF8.GetBytes(Message);
            try
            {
                ICryptoTransform Encryptor = TDESAlgorithm.CreateEncryptor();
                Results = Encryptor.TransformFinalBlock(DataToEncrypt, 0, DataToEncrypt.Length);
            }
            finally
            {
                TDESAlgorithm.Clear();
                HashProvider.Clear();
            }
            return Convert.ToBase64String(Results);
        }

        public static string DecryptString(string Message)
        {
            Message = Message.Replace(" ", "+");
            byte[] Results;
            System.Text.UTF8Encoding UTF8 = new System.Text.UTF8Encoding();
            MD5CryptoServiceProvider HashProvider = new MD5CryptoServiceProvider();
            byte[] TDESKey = HashProvider.ComputeHash(UTF8.GetBytes(passphrase));
            TripleDESCryptoServiceProvider TDESAlgorithm = new TripleDESCryptoServiceProvider();
            TDESAlgorithm.Key = TDESKey;
            TDESAlgorithm.Mode = CipherMode.ECB;
            TDESAlgorithm.Padding = PaddingMode.PKCS7;
            byte[] DataToDecrypt = Convert.FromBase64String(Message);
            try
            {
                ICryptoTransform Decryptor = TDESAlgorithm.CreateDecryptor();
                Results = Decryptor.TransformFinalBlock(DataToDecrypt, 0, DataToDecrypt.Length);
            }
            finally
            {
                TDESAlgorithm.Clear();
                HashProvider.Clear();
            }
            return UTF8.GetString(Results);
        }
        #endregion

        public UserApprovalModel GetunapprovedUsers()
        {
            UserApprovalModel ua = new UserApprovalModel();
            MembershipUser currentuser = Membership.GetUser();
            string adminEmail = currentuser.Email;
            MembershipUserCollection AllUser = Membership.GetAllUsers();
            ua.Users = new System.Collections.Generic.List<UserApprovalModel.approveduser>();
            UserApprovalModel.approveduser uas;
            foreach (MembershipUser mu in AllUser)
            {
                if (!mu.IsApproved)
                {
                    MyCustomProfile profile = MyCustomProfile.GetProfile(mu.UserName);
                    MembershipUserCollection AllAdmins = Membership.FindUsersByEmail(profile.ContactEmail);
                    if (AllAdmins.Count == 0)
                    {
                        if (ViewBag.IsAdministrator)
                        {
                            uas = new UserApprovalModel.approveduser();
                            uas.UserName = mu.UserName;
                            uas.Fname = profile.FirstName;
                            uas.Lname = profile.LastName;
                            uas.Email = mu.Email;
                            uas.Application = profile.Application;
                            ua.Users.Add(uas);
                        }
                    }
                    else
                    {
                        if (profile.ContactEmail == adminEmail)
                        {
                            uas = new UserApprovalModel.approveduser();
                            uas.UserName = mu.UserName;
                            uas.Fname = profile.FirstName;
                            uas.Lname = profile.LastName;
                            uas.Application = profile.Application;
                            uas.Email = mu.Email;

                            ua.Users.Add(uas);
                        }
                    }

                }
            }

            if (ua.Users.Count <= 0)
            {
                ViewData["gridEmpty"] = "No Record(s) to display!";
            }
            else
            {
                ViewData["gridEmpty"] = string.Empty;
            }

            return ua;
        }
        public AssignUserRolesModel GetapprovedUsers(AssignUserRolesModel aum)
        {
            UserApprovalModel ua = new UserApprovalModel();
            MembershipUser currentuser = Membership.GetUser();
            MyCustomProfile adminprofile = MyCustomProfile.GetProfile(currentuser.UserName);
            string adminApplication = adminprofile.Application;
            adminApplication = adminApplication.ToLower();
            MembershipUserCollection AllUser = Membership.GetAllUsers();           
            aum.Users = new System.Collections.Generic.List<AssignUserRolesModel.approveduser>();
            AssignUserRolesModel.approveduser au;
            foreach (MembershipUser mu in AllUser)
            {
                if (mu.IsApproved && mu.UserName != currentuser.UserName)
                {
                    if (ViewBag.IsAdministrator)
                    {
                        au = new AssignUserRolesModel.approveduser();
                        au.UserName = mu.UserName;
                        au.UserId = mu.ProviderUserKey.ToString();
                        aum.Users.Add(au);
                    }
                    else
                    {
                        MyCustomProfile profile = MyCustomProfile.GetProfile(mu.UserName);
                        if (profile.Application.ToLower() == adminApplication)
                        {
                            au = new AssignUserRolesModel.approveduser();
                            au.UserName = mu.UserName;
                            au.UserId = mu.ProviderUserKey.ToString();

                            aum.Users.Add(au);
                        }
                    }

                }
            }

            if (aum.Users.Count <= 0)
            {
                ViewData["ListEmpty"] = "No Record(s) to display!";
            }
            else
            {
                ViewData["ListEmpty"] = string.Empty;
            }
            return aum;
        }
        public string getCurrentUserRole()
        {
            string Role = string.Empty;
            if (HttpContext.User.Identity.IsAuthenticated)
                Role = Convert.ToString(Roles.GetRolesForUser(HttpContext.User.Identity.Name).FirstOrDefault());
            return Role;
        }
        public void SaveRolestoUser(AssignUserRolesModel model)
        {
            try
            {
                using (SqlCeConnection c = new SqlCeConnection(ConfigurationManager.ConnectionStrings["ProviderDB"].ToString()))
                {
                    string Userid = Session["SelectedUser"].ToString();

                    c.Open();
                    foreach (var role in model.SelectedRoles)
                    {
                        SqlCeCommand cmd = new SqlCeCommand("insert into UsersInRoles values('" + Userid + "','" + role + "')", c);
                        cmd.ExecuteNonQuery();
                    }
                    c.Close();
                }
            }
            catch (Exception ex)
            { }
        }
        public void SaveRoles(List<string> roles)
        {
            try
            {
                using (SqlCeConnection c = new SqlCeConnection(ConfigurationManager.ConnectionStrings["ProviderDB"].ToString()))
                {
                    string Userid = Session["SelectedUser"].ToString();
                    c.Open();
                    foreach (var role in roles)
                    {
                        SqlCeCommand cmd = new SqlCeCommand("insert into UsersInRoles values('" + Userid + "','" + role + "')", c);
                        cmd.ExecuteNonQuery();
                    }
                    c.Close();
                }
            }
            catch (Exception ex)
            { }
        }
        public void DeleteRolesbyUser()
        {
            try
            {
                using (SqlCeConnection c = new SqlCeConnection(ConfigurationManager.ConnectionStrings["ProviderDB"].ToString()))
                {
                    string Userid = Session["SelectedUser"].ToString();

                    c.Open();

                    SqlCeCommand cmd = new SqlCeCommand("DELETE FROM [UsersInRoles] WHERE (Userid ='" + Userid + "')", c);
                    cmd.ExecuteNonQuery();
                    c.Close();

                }
            }
            catch (Exception ex)
            { }
        }
        public DataTable GetRolesByApplication(string ApplicationName)
        {
            DataTable t = new DataTable();
            using (SqlCeConnection c = new SqlCeConnection(ConfigurationManager.ConnectionStrings["ProviderDB"].ToString()))
            {

                using (SqlCeDataAdapter a = new SqlCeDataAdapter(
                      "SELECT Applications.ApplicationName, Roles.RoleName,Roles.RoleId FROM Applications INNER JOIN Roles ON Applications.ApplicationId = Roles.ApplicationId where Applications.ApplicationName ='" + ApplicationName + "' ORDER BY Applications.ApplicationName", c))
                {
                    a.Fill(t);
                }
            }
            return t;
        }
        public DataTable GetRolesByUser()
        {
            DataTable t = new DataTable();
            using (SqlCeConnection c = new SqlCeConnection(ConfigurationManager.ConnectionStrings["ProviderDB"].ToString()))
            {
                using (SqlCeDataAdapter a = new SqlCeDataAdapter(
                       "SELECT Applications.ApplicationName, Roles.RoleName, Roles.RoleId FROM Applications INNER JOIN Roles ON Applications.ApplicationId = Roles.ApplicationId INNER JOIN UsersInRoles ON Roles.RoleId = UsersInRoles.RoleId WHERE (UsersInRoles.UserId = '" + Session["SelectedUser"].ToString() + "')", c))
                {
                    a.Fill(t);
                }
            }
            return t;
        }

        #endregion
     
    }
}
