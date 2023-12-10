using System.ComponentModel.DataAnnotations;

namespace Nexus_Void.Models
{
    public class WishlistModel
    {
        [Key]
        public int ID { get; set; }
        [Required]
        public string username { get; set; }
        [Required]
        public string data { get; set; }

    }
}
