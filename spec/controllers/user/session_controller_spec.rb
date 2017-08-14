# -*- encoding : utf-8 -*-
require 'spec_helper'

describe User::SessionController do

  before do
    # Don't call out to external url during tests
    allow(controller).to receive(:country_from_ip).and_return('gb')
  end

  describe 'GET new' do

    it "should show sign in / sign up page" do
      get :new
      expect(response.body).to render_template('user/sign')
    end

    it "should create post redirect to / when you just go to /signin" do
      get :new
      post_redirect = get_last_post_redirect
      expect(post_redirect.uri).to eq("/")
    end

    it "should create post redirect to /list when you click signin on /list" do
      get :new, :r => "/list"
      post_redirect = get_last_post_redirect
      expect(post_redirect.uri).to eq("/list")
    end
  end

  describe 'POST create' do
    let(:user) { FactoryGirl.create(:user) }

    it "sets a the cookie expiry to nil on next page load" do
      post :create, { :user_signin => { :email => user.email,
                                        :password => 'jonespassword' } }
      get :new
      expect(request.env['rack.session.options'][:expire_after]).to be_nil
    end

    it "does not log you in if you use an invalid PostRedirect token" do
      post_redirect = "something invalid"
      post :create, { :user_signin => { :email => 'bob@localhost',
                                        :password => 'jonespassword' },
                      :token => post_redirect }
      expect(response).to render_template('sign')
      expect(assigns[:post_redirect]).to eq(nil)
    end

    context "checking 'remember_me'" do
      let(:user) do
        FactoryGirl.create(:user,
                           :password => 'password',
                           :email_confirmed => true)
      end

      def do_signin(email, password)
        post :create, { :user_signin => { :email => email,
                                          :password => password },
                        :remember_me => "1" }
      end

      before do
        # fake an expired previous session which has not been reset
        # (i.e. it timed out rather than the user signing out manually)
        session[:ttl] = Time.zone.now - 2.months
      end

      it "logs the user in" do
        do_signin(user.email, 'password')
        expect(session[:user_id]).to eq(user.id)
      end

      it "sets session[:remember_me] to true" do
        do_signin(user.email, 'password')
        expect(session[:remember_me]).to eq(true)
      end

      it "clears the session[:ttl] value" do
        do_signin(user.email, 'password')
        expect(session[:ttl]).to be_nil
      end

      it "sets a long lived cookie on next page load" do
        do_signin(user.email, 'password')
        get :new
        expect(request.env['rack.session.options'][:expire_after]).
          to eq(1.month)
      end
    end
  end

  describe 'GET destroy' do
    let(:user) { FactoryGirl.create(:user) }

    it "logs you out and redirect to the home page" do
      get :destroy, {}, { :user_id => user.id }
      expect(session[:user_id]).to be_nil
      expect(response).to redirect_to(frontpage_path)
    end

    it "logs you out and redirect you to where you were" do
      get :destroy, { :r => '/list' }, { :user_id => user.id }
      expect(session[:user_id]).to be_nil
      expect(response).
        to redirect_to(request_list_path)
    end

    it "clears the session ttl" do
      get :destroy, {}, { :user_id => user.id, :ttl => Time.zone.now }
      expect(session[:ttl]).to be_nil
    end

  end

  describe 'GET confirm' do

    context 'if the post redirect cannot be found' do

      it 'renders bad_token' do
        get :confirm, { :email_token => '' }
        expect(response).to render_template(:bad_token)
      end

    end

    context 'the post redirect circumstance is login_as' do

      before :each do
        @user = FactoryGirl.create(:user, :email_confirmed => false)
        @post_redirect =
          PostRedirect.
            create(:uri => '/', :user => @user, :circumstance => 'login_as')

        get :confirm, { :email_token => @post_redirect.email_token }
      end

      it 'confirms the post redirect user' do
        expect(@user.reload.email_confirmed).to eq(true)
      end

      it 'logs in as the post redirect user' do
        expect(session[:user_id]).to eq(@user.id)
      end

      it 'sets the user_circumstance to login_as' do
        expect(session[:user_circumstance]).to eq('login_as')
      end

      it 'redirects to the post redirect uri' do
        expect(response).to redirect_to('/?post_redirect=1&context=confirm')
      end

    end

    context 'the post redirect circumstance is change_password' do

      before :each do
        @user = FactoryGirl.create(:user)
        @post_redirect =
          PostRedirect.create(:uri => edit_password_change_path,
                              :user => @user,
                              :circumstance => 'change_password')

        get :confirm, { :email_token => @post_redirect.email_token }
      end

      it 'sets the change_password_post_redirect_id session key' do
        expect(session[:change_password_post_redirect_id]).
          to eq(@post_redirect.id)
      end

      it 'does not log the user in' do
        expect(session[:user_id]).to eq(nil)
      end

      it 'logs out a user who does not own the post redirect' do
        logged_in_user = FactoryGirl.create(:user)
        @user = FactoryGirl.create(:user, :email_confirmed => false)
        @post_redirect =
          PostRedirect.create(:uri => edit_password_change_path,
                              :user => @user,
                              :circumstance => 'change_password')

        session[:user_id] = logged_in_user.id
        get :confirm, { :email_token => @post_redirect.email_token }

        expect(session[:user_id]).to be_nil
      end

      it 'does not log out a user if they own the post redirect' do
        @user = FactoryGirl.create(:user, :email_confirmed => false)
        @post_redirect =
          PostRedirect.create(:uri => edit_password_change_path,
                              :user => @user,
                              :circumstance => 'change_password')

        session[:user_id] = @user.id
        get :confirm, { :email_token => @post_redirect.email_token }

        expect(session[:user_id]).to eq(@user.id)
        expect(assigns[:user]).to eq(@user)
      end

      it 'does not confirm an unconfirmed user' do
        @user = FactoryGirl.create(:user, :email_confirmed => false)
        @post_redirect =
          PostRedirect.create(:uri => edit_password_change_path,
                              :user => @user,
                              :circumstance => 'change_password')

        get :confirm, { :email_token => @post_redirect.email_token }

        expect(@user.reload.email_confirmed).to eq(false)
      end

      it 'sets the user_circumstance to change_password' do
        expect(session[:user_circumstance]).to eq('change_password')
      end

      it 'redirects to the post redirect uri' do
        expect(response).
          to redirect_to('/profile/change_password?' \
                         'post_redirect=1&context=confirm')
      end

    end

    context 'if the currently logged in user is an admin' do

      before :each do
        @admin = FactoryGirl.create(:admin_user)
        @user = FactoryGirl.create(:user, :email_confirmed => false)
        @post_redirect = PostRedirect.create(:uri => '/', :user => @user)

        session[:user_id] = @admin.id
        get :confirm, { :email_token => @post_redirect.email_token }
      end

      it 'does not confirm the post redirect user' do
        expect(@user.reload.email_confirmed).to eq(false)
      end

      it 'stays logged in as the admin user' do
        expect(session[:user_id]).to eq(@admin.id)
      end

      it 'sets the user_circumstance to normal' do
        expect(session[:user_circumstance]).to eq('normal')
      end

      it 'redirects to the post redirect uri' do
        expect(response).to redirect_to('/?post_redirect=1&context=confirm')
      end

    end

    context <<-EOF do
      if the currently logged in user is not an admin and owns the post
       redirect
    EOF

      before :each do
        @user = FactoryGirl.create(:user, :email_confirmed => false)
        @post_redirect = PostRedirect.create(:uri => '/', :user => @user)

        session[:user_id] = @user.id
        get :confirm, { :email_token => @post_redirect.email_token }
      end

      it 'confirms the post redirect user' do
        expect(@user.reload.email_confirmed).to eq(true)
      end

      it 'stays logged in as the user' do
        expect(session[:user_id]).to eq(@user.id)
      end

      it 'sets the user_circumstance to normal' do
        expect(session[:user_circumstance]).to eq('normal')
      end

      it 'redirects to the post redirect uri' do
        expect(response).to redirect_to('/?post_redirect=1&context=confirm')
      end

    end

    context <<-EOF do
      if the currently logged in user is not an admin and does not own the post
       redirect
    EOF
      before :each do
        @current_user = FactoryGirl.create(:user)
        @user = FactoryGirl.create(:user, :email_confirmed => false)
        @post_redirect = PostRedirect.create(:uri => '/', :user => @user)

        session[:user_id] = @current_user.id
        get :confirm, { :email_token => @post_redirect.email_token }
      end

      it 'confirms the post redirect user' do
        expect(@user.reload.email_confirmed).to eq(true)
      end

      # FIXME: There's no reason this should be allowed
      it 'gets logged in as the post redirect user' do
        expect(session[:user_id]).to eq(@user.id)
      end

      it 'sets the user_circumstance to normal' do
        expect(session[:user_circumstance]).to eq('normal')
      end

      it 'redirects to the post redirect uri' do
        expect(response).to redirect_to('/?post_redirect=1&context=confirm')
      end

    end

    context 'if there is no logged in user' do

      before :each do
        @user = FactoryGirl.create(:user, :email_confirmed => false)
        @post_redirect = PostRedirect.create(:uri => '/', :user => @user)

        get :confirm, { :email_token => @post_redirect.email_token }
      end

      it 'confirms the post redirect user' do
        expect(@user.reload.email_confirmed).to eq(true)
      end

      it 'gets logged in as the post redirect user' do
        expect(session[:user_id]).to eq(@user.id)
      end

      it 'sets the user_circumstance to normal' do
        expect(session[:user_circumstance]).to eq('normal')
      end

      it 'redirects to the post redirect uri' do
        expect(response).to redirect_to('/?post_redirect=1&context=confirm')
      end

    end
  end

end
