using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.ComponentModel.DataAnnotations;
using System.Web.Security;

namespace Thinktecture.IdentityServer.Web.ViewModels
{
    
    public class UserApprovalModel
    {

        
        #region property
         public class approveduser
         {
             public string UserName { get; set; }
             public string UserApproval { get; set; }
             public string Fname { get; set; }
             public string Lname { get; set; }
             public string Email { get; set; }
             public string Application { get; set; }
         }

         public List<approveduser> Users { get; set; }

        
        #endregion
    }


}