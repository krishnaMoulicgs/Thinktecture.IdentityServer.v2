/*
 * Copyright (c) Dominick Baier.  All rights reserved.
 * see license.txt
 */

using System;
using System.ComponentModel.DataAnnotations;

namespace Thinktecture.IdentityServer.Web.ViewModels
{
    public class ForgotPassword
    {
        [Required]        
        [Display(Name = "UserName", ResourceType = typeof(Resources.ForgotPassword))]
        public string UserName { get; set; }

        [Required]
        [EmailAddress(ErrorMessage = "Invalid Email Address")]
        [Display(Name = "EmailId", ResourceType = typeof(Resources.ForgotPassword))]
        public string EmailId { get; set; }

        [Display(Name = "Result", ResourceType = typeof(Resources.ForgotPassword))]
        public string Result { get; set; }
       
        public string ReturnUrl { get; set; }
       
    }
}