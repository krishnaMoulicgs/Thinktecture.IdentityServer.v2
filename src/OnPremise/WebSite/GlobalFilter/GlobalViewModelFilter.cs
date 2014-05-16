/*
 * Copyright (c) Dominick Baier.  All rights reserved.
 * see license.txt
 */

using System.ComponentModel.Composition;
using System.Web.Mvc;
using Thinktecture.IdentityModel.Authorization;
using Thinktecture.IdentityServer.Repositories;
using System.Data.SqlServerCe;
using System;
using System.Configuration;
using System.Data;

namespace Thinktecture.IdentityServer.Web.GlobalFilter
{
    public class GlobalViewModelFilter : ActionFilterAttribute
    {
        [Import]
        public IConfigurationRepository ConfigurationRepository { get; set; }

        public override void OnActionExecuting(ActionExecutingContext filterContext)
        {
            Container.Current.SatisfyImportsOnce(this);

            filterContext.Controller.ViewBag.SiteName = ConfigurationRepository.Global.SiteName;
            filterContext.Controller.ViewBag.IsAdministrator = ClaimsAuthorization.CheckAccess(Constants.Actions.Administration, Constants.Resources.UI);
            filterContext.Controller.ViewBag.IsRoleAdmin = ClaimsAuthorization.CheckAccess(Constants.Actions.RoleAdmin, Constants.Resources.UI); //true; // "RoleAdmin"; //GetRoleByUserName(filterContext.HttpContext.User.Identity.Name);
            filterContext.Controller.ViewBag.IsSignedIn = filterContext.HttpContext.User.Identity.IsAuthenticated;         
            base.OnActionExecuting(filterContext);
        }


        //protected bool GetRoleByUserName(string username)
        //{
        //    bool result = false;
        //    using (SqlCeConnection c = new SqlCeConnection(ConfigurationManager.ConnectionStrings["ProviderDB"].ToString()))
        //    {
        //        string cmdstr = "SELECT Roles.RoleName FROM Roles INNER JOIN UsersInRoles ON Roles.RoleId = UsersInRoles.RoleId INNER JOIN  Users ON UsersInRoles.UserId = Users.UserId WHERE (Users.UserName = '" + username + "')";
        //        c.Open();
        //        SqlCeCommand cmd = new SqlCeCommand(cmdstr, c);
        //        using (SqlCeDataAdapter a = new SqlCeDataAdapter(cmdstr, c))
        //        {
        //            DataTable dtApplication = new DataTable();
        //            a.Fill(dtApplication);
        //            if (dtApplication != null && dtApplication.Rows.Count > 0)
        //            {
        //                foreach (DataRow drow in dtApplication.Rows)
        //                {
        //                    if (drow.ItemArray[0].ToString() == "RoleAdmin")
        //                    {
        //                        result = true;
        //                    }
        //                }
        //            }
        //            else
        //            {
        //                result = false;
        //            }
        //        }
        //        c.Close();
        //    }

        //    return result;
        //}
    }
      
}