using System.ComponentModel.DataAnnotations;

namespace Application.DTOs.RequestDTOs
{
    public class UpdateUserDTO
    {
        /// <summary>
        /// User ID
        /// </summary>
        [Required(ErrorMessage = "User ID is required")]
        public Guid UserId { get; set; }

        /// <summary>
        /// Email
        /// </summary>
        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid email format")]
        [StringLength(100, ErrorMessage = "Email cannot exceed 100 characters")]
        public string Email { get; set; } = null!;

        /// <summary>
        /// Password
        /// </summary>
        [Required(ErrorMessage = "Password is required")]
        [StringLength(100, MinimumLength = 6, ErrorMessage = "Password must be at least 6 characters")]
        public string Password { get; set; } = null!;

        /// <summary>
        /// Phone Number
        /// </summary>
        [Phone(ErrorMessage = "Invalid phone number format")]
        [StringLength(10, ErrorMessage = "Phone number cannot exceed 10 characters")]
        public string? PhoneNumber { get; set; }

        /// <summary>
        /// Updated At
        /// </summary>
        public DateTime? UpdatedAt { get; set; }
    }
}
