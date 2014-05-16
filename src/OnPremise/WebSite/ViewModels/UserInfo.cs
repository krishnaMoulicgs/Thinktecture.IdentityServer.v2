using System;
using System.ComponentModel.DataAnnotations;

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
        #endregion

        #region   

        //If needed, you can provide methods to recover profiles 
        //for the logged in user or any user given its user name
        public static MyCustomProfile GetCurrent()
        {
            return Create(Membership.GetUser().UserName) as MyCustomProfile;
        }

        public static MyCustomProfile GetProfile(string userName)
        {
            return Create(userName) as MyCustomProfile;
        }
        #endregion
    }
}