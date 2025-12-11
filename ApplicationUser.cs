using Microsoft.AspNetCore.Identity;

namespace ECommerceAuthMVC.Models
{
    public class ApplicationUser : IdentityUser
    {
        public string? FullName { get; set; }
    }
}
 
