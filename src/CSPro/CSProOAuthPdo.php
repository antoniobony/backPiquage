<?php
namespace App\CSPro;
use OAuth2\Storage\Pdo;
class CSProOAuthPdo extends Pdo
{
//override users table if you want to use custom users table instead of oauth_users
 public function __construct($connection, $config = [])
    {
        parent::__construct($connection, $config);
		$this->config['user_table'] = 'cspro_users';
    }


//Using php password_verify to check for the password hash that contains the algorithm and salt.
//Uses PHP >=5.5.9
//override check password 
 protected function checkPassword($user, $password) : bool
    {
        //return password_verify($password,$user['password']);
        if (isset($user['actif']) && (int) $user['actif'] === 0) {
            return false;
        }
    
        if (!password_verify($password, $user['password'])) {
            return false;
        }
    
        // Authentification réussie : enregistrer la dernière connexion
        try {
            $stmt = $this->db->prepare(sprintf(
                'UPDATE %s SET derniere_connexion = NOW(), modified_time = modified_time WHERE username = :username',
                $this->config['user_table']
            ));
            $stmt->execute(['username' => $user['username']]);
        } catch (\Exception $e) {
            // ne jamais bloquer une connexion pour un simple horodatage
        }
    
        return true;
    }
}