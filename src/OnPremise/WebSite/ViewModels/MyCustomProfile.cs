using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Profile;

namespace Thinktecture.IdentityServer.Web.ViewModels
{
    [Serializable()]
    public class MyCustomProfile : ProfileBase
    {

        #region Properties
        public string FirstName
        {
            get { return base["FirstName"] as string; }
            set { base["FirstName"] = value; }
        }
        public string LastName
        {
            get { return base["LastName"] as string; }
            set { base["LastName"] = value; }
        }
        public string Company
        {
            get { return base["Company"] as string; }
            set { base["Company"] = value; }
        }
        public string ContactEmail
        {
            get { return base["ContactEmail"] as string; }
            set { base["ContactEmail"] = value; }
        }
        public string Application
        {
            get { return base["Application"] as string; }
            set { base["Application"] = value; }
        }
        public string Status
        {
            get { return base["Status"] as string; }
            set { base["Status"] = value; }
        }
        #endregion

        public static MyCustomProfile GetProfile(string userName)
        {
            return Create(userName) as MyCustomProfile;
        }
    }
}