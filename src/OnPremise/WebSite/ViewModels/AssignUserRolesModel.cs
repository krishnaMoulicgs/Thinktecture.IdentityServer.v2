using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Data;

namespace Thinktecture.IdentityServer.Web.ViewModels
{
    public class AssignUserRolesModel
    {
        public class approveduser
        {
            public string UserName { get; set; }
            public string UserId { get; set; }
        }

        public IEnumerable<string> SelectedRoles { get; set; }
        public string Username { get; set;  }
        public string UserRole { get; set; }
        public string Time { get; set; }
        public string Application { get; set; }
        public List<approveduser> Users { get; set; }
        public List<userRoles> UserRolesTable { get; set; }
        public List<userRoles> RolesinUserTable { get; set; }
        public string ValueField { get; set; }

        public List<BindViewModel> BindList { get; set; }
    }
    public class BindViewModel
    {
        public string ValueField { get; set; }
        public string TextField { get; set; }
        public string Abbre { get; set; }
    }

    public class userRoles
    {
        public class Role
        {
            public string Rolename { get; set; }
            public string RoleId { get; set; }          
        }

        public string Application { get; set; }
        public List<Role> Roles { get; set; }
    }
}
