# -*- encoding : utf-8 -*-
require File.expand_path(File.dirname(__FILE__) + '/../../spec_helper')
require 'stripe_mock'

describe AlaveteliPro::PaymentMethodsController do
  let(:stripe_helper) { StripeMock.create_test_helper }

  before do
    StripeMock.start
    stripe_helper.create_plan(id: 'pro', amount: 1000)
  end

  after do
    StripeMock.stop
  end

  describe 'POST #update' do

    context 'without a signed-in user' do

      before do
        post :update
      end

      it 'redirects to the login form' do
        expect(response).
          to redirect_to(signin_path(:token => PostRedirect.last.token))
      end

    end

    context 'with a signed-in user' do
      let(:user) { FactoryGirl.create(:pro_user) }

      let(:customer) do
        customer = Stripe::Customer.
                     create(email: user.email,
                            source: stripe_helper.generate_card_token)
        user.pro_account.stripe_customer_id = customer.id
        user.pro_account.save
        customer
      end

      let(:token) { stripe_helper.generate_card_token }
      let(:old_card_id) { customer.sources.first.id }

      before do
        session[:user_id] = user.id
        post :update, 'stripeToken' => token,
                      'old_card_id' => old_card_id
      end

      it 'finds the card token' do
        expect(assigns(:token).id).to eq(token)
      end

      it 'finds the id of the card being updated' do
        expect(assigns(:old_card_id)).to eq(old_card_id)
      end

      it 'retrieves the correct Stripe customer' do
        expect(assigns(:customer).id).
          to eq(user.pro_account.stripe_customer_id)
      end

      it 'redirects to the account page' do
        expect(response).to redirect_to(account_path)
      end

      context 'with a successful transaction' do

        it 'adds the new card to the Stripe customer' do
          reloaded = Stripe::Customer.
                       retrieve(user.pro_account.stripe_customer_id)
          expect(reloaded.sources.data.map(&:id)).
            to include(assigns(:token).card.id)
        end

        it 'removes the old card from the Stripe customer' do
          reloaded = Stripe::Customer.
                       retrieve(user.pro_account.stripe_customer_id)
          expect(reloaded.sources.data.map(&:id)).
            to_not include(old_card_id)
        end

        it 'shows a message to confirm the update' do
          expect(flash[:notice]).to eq('Your payment details have been updated')
        end

      end

    end

  end

end
