using System.ComponentModel.DataAnnotations;

namespace Identity.Application.Dtos.Users
{
    public class RegisterDto
    {
        [Required]
        public string UserName { get; set; }

        [Required]
        public string Password { get; set; }

        [Required]
        public string Email { get; set; }

        [Required]
        public string FirstName { get; set; }

        [Required]
        public string LastName { get; set; }

        [Required]
        [StringLength(50)]
        public string DisplayName { get; set; }

        [StringLength(500)]
        public string? Bio { get; set; }

        [Url]
        public string? ProfilePictureUrl { get; set; }

        public bool IsManager { get; set; }

        public IList<string>? Roles { get; set; }

        public IList<ClaimDto>? Claims { get; set; }
    }
}