class RemoveAuth0Oauth2UserInfo < ActiveRecord::Migration
  def up
    r = execute <<SQL
      DELETE FROM oauth2_user_infos
      WHERE provider = 'Auth0'
SQL
  end

  def down
    raise ActiveRecord::IrreversibleMigration
  end
end
