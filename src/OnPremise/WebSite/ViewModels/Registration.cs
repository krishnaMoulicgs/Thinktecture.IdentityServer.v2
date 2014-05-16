/*
 * Copyright (c) Dominick Baier.  All rights reserved.
 * see license.txt
 */

using System;
using System.ComponentModel.DataAnnotations;

namespace Thinktecture.IdentityServer.Web.ViewModels
{
    public class Registration
    {
       
        [Display(Name = "FirstName", ResourceType = typeof(Resources.Registration))]
        public string FirstName { get; set; }

        [Display(Name = "LastName", ResourceType = typeof(Resources.Registration))]
        public string LastName { get; set; }

        [Display(Name = "Company", ResourceType = typeof(Resources.Registration))]
        public string Company { get; set; }
      
        [Required]
        [EmailAddress(ErrorMessage = "Invalid Email Address")]
        [Display(Name = "EmailId", ResourceType = typeof(Resources.Registration))]
        public string EmailId { get; set; }
        
        [Required]
        [Display(Name = "UserName", ResourceType = typeof(Resources.Registration))]
        public string UserName { get; set; }

        [Required]
        [Display(Name = "Password", ResourceType = typeof(Resources.Registration))]
        public string Password { get; set; }
        
        [Required]
        [Compare("Password", ErrorMessage = "The password and confirmation password does not match.")]
        [Display(Name = "ConfirmPassword", ResourceType = typeof(Resources.Registration))]
        public string ConfirmPassword { get; set; }

        [Required]
        [Display(Name = "ContactEmail", ResourceType = typeof(Resources.Registration))]
        public string ContactMailId { get; set; }

        [Required]
        [Display(Name = "Application", ResourceType = typeof(Resources.Registration))]
        public string Application { get; set; }


        public string ReturnUrl { get; set; }

              
    }
}